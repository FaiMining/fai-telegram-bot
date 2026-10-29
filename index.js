const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const { Telegraf } = require('telegraf');

const app = express();
app.use(express.json());
app.use(cors());

// Safe Firebase Initialization
let serviceAccount;
try {
  serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
} catch (e) {
  console.error("❌ FIREBASE_SERVICE_ACCOUNT JSON parse error:", e.message);
  process.exit(1);
}

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "https://fai-mining-app-default-rtdb.firebaseio.com"
});

const db = admin.database();

// Telegram Bot Setup
const BOT_TOKEN = process.env.BOT_TOKEN;
const CHANNEL_USERNAME = '@VerifyCryptoMining';
const bot = new Telegraf(BOT_TOKEN);

// Bot Command: Send OTP to User
bot.command('getcode', async (ctx) => {
  const telegramUserId = ctx.from.id.toString();

  try {
    // 1. Check if user already claimed task using this Telegram ID
    const claimedSnap = await db.ref(`claimedTelegramIds/${telegramUserId}`).once('value');
    if (claimedSnap.val() === true) {
      return ctx.reply(`❌ You have already verified a task using this Telegram account! Each user can only claim the reward once.`);
    }

    // 2. Check if user has joined Telegram Channel
    const member = await ctx.telegram.getChatMember(CHANNEL_USERNAME, ctx.from.id);
    const isMember = ['creator', 'administrator', 'member'].includes(member.status);

    if (!isMember) {
      return ctx.reply(`❌ You haven't joined our channel yet! Please join first: ${CHANNEL_USERNAME}`);
    }

    // 3. Generate 6-digit Random OTP Code
    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();

    // Save OTP to Database
    await db.ref(`otps/${otpCode}`).set({
      telegramId: telegramUserId,
      used: false,
      createdAt: Date.now(),
      expiresAt: Date.now() + (10 * 60 * 1000) // 10 minutes validity
    });

    return ctx.reply(`✅ Your 6-digit OTP verification code: ${otpCode}\n\n⚠️ This code can only be used once and is bound to your Telegram ID.`);

  } catch (error) {
    console.error('Error in getcode command:', error);
    return ctx.reply('⚠️ Service error! Please try again later.');
  }
});

bot.launch();

// 4. Web App Task Verification API Endpoint (With Telegram ID Binding)
app.post('/api/verify-task', async (req, res) => {
  const { code, userCode } = req.body; // userCode = Web App User UID (e.g., CCW12345)

  if (!code || code.length !== 6 || !userCode) {
    return res.status(400).json({ status: 'error', message: 'Invalid request data!' });
  }

  try {
    const otpRef = db.ref(`otps/${code}`);
    const snapshot = await otpRef.once('value');
    const otpData = snapshot.val();

    // Check 1: OTP exists
    if (!otpData) {
      return res.status(400).json({ status: 'error', message: 'Invalid OTP Code!' });
    }

    // Check 2: OTP already used
    if (otpData.used === true) {
      return res.status(400).json({ status: 'error', message: 'This OTP code has already been used!' });
    }

    // Check 3: OTP expired
    if (Date.now() > otpData.expiresAt) {
      return res.status(400).json({ status: 'error', message: 'This OTP code has expired!' });
    }

    const telegramId = otpData.telegramId;

    // Check 4: TELEGRAM ID BINDING CHECK (Critical Security)
    const claimedSnap = await db.ref(`claimedTelegramIds/${telegramId}`).once('value');
    if (claimedSnap.val() === true) {
      await otpRef.update({ used: true });
      return res.status(400).json({ status: 'error', message: 'This Telegram ID has already been used to verify an account!' });
    }

    // Mark OTP as Used & Lock Telegram ID permanently
    const updates = {};
    updates[`otps/${code}/used`] = true;
    updates[`otps/${code}/usedAt`] = Date.now();
    updates[`claimedTelegramIds/${telegramId}`] = true; // Lock this Telegram ID

    await db.ref().update(updates);

    return res.json({ 
      status: 'success', 
      message: 'OTP verified & Telegram ID bound successfully!',
      telegramId: telegramId 
    });

  } catch (error) {
    console.error('Error verifying OTP:', error);
    return res.status(500).json({ status: 'error', message: 'Internal Server Error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Verification Server running on port ${PORT}`);
});
