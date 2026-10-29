const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const { Telegraf } = require('telegraf');

const app = express();
app.use(express.json());
app.use(cors());

// Firebase Admin SDK Initialization
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

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
      return ctx.reply(`❌ Apnar ei Telegram account theke agei ekbar task verify kora hoyeche! Prottek user shudhu 1 bar reward pete paren.`);
    }

    // 2. Check if user has joined Telegram Channel
    const member = await ctx.telegram.getChatMember(CHANNEL_USERNAME, ctx.from.id);
    const isMember = ['creator', 'administrator', 'member'].includes(member.status);

    if (!isMember) {
      return ctx.reply(`❌ Apni ekono amader channel-e join korni! Age join korun: ${CHANNEL_USERNAME}`);
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

    return ctx.reply(`✅ Apnar 6-digit OTP verification code: ${otpCode}\n\n⚠️ Ei code-ti shudhu 1 bar ebong apnar ei Telegram ID diyei use kora jabe.`);

  } catch (error) {
    console.error('Error in getcode command:', error);
    return ctx.reply('⚠️ Service error! Pore abar chesta korun.');
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
      return res.status(400).json({ status: 'error', message: 'Ei OTP code-ti agei use kora hoye geche!' });
    }

    // Check 3: OTP expired
    if (Date.now() > otpData.expiresAt) {
      return res.status(400).json({ status: 'error', message: 'Ei OTP code-er meyad shesh (Expired)!' });
    }

    const telegramId = otpData.telegramId;

    // Check 4: TELEGRAM ID BINDING CHECK (Critical Security)
    const claimedSnap = await db.ref(`claimedTelegramIds/${telegramId}`).once('value');
    if (claimedSnap.val() === true) {
      // Mark this attempted code as used too just in case
      await otpRef.update({ used: true });
      return res.status(400).json({ status: 'error', message: 'Ei Telegram ID diye already onno account-e task verify kora hoyeche!' });
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
