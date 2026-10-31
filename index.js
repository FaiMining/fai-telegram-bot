
const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const { Telegraf } = require('telegraf');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(cors());

// Firebase Initialization
let serviceAccount;
try {
  serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
} catch (e) {
  console.error('FIREBASE_SERVICE_ACCOUNT JSON parse error:', e.message);
  process.exit(1);
}

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: 'https://fai-mining-app-default-rtdb.firebaseio.com'
});
const db = admin.database();

// Email OTP Configuration
const GMAIL_USER = process.env.GMAIL_USER;
const GMAIL_APP_PASSWORD = process.env.GMAIL_APP_PASSWORD;
const OTP_EMAIL_ENABLED = process.env.OTP_EMAIL_ENABLED === 'true';
const otpSecret = process.env.OTP_HASH_SECRET || serviceAccount.private_key;

let transporter = null;
if (OTP_EMAIL_ENABLED && GMAIL_USER && GMAIL_APP_PASSWORD) {
  transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: {
      user: GMAIL_USER,
      pass: GMAIL_APP_PASSWORD.replace(/\s/g, '')
    }
  });
} else {
  console.warn('Email OTP is disabled or Gmail settings are missing.');
}

function hashOTP(email, code) {
  return crypto.createHmac('sha256', otpSecret)
    .update(`${email}:${code}`).digest('hex');
}

function isGmail(email) {
  return /^[a-zA-Z0-9._%+-]+@gmail\.com$/i.test(email);
}

function isStrongPassword(password) {
  return typeof password === 'string' &&
    password.length >= 8 &&
    /[A-Z]/.test(password) &&
    /[a-z]/.test(password) &&
    /[0-9]/.test(password) &&
    /[!@#$%^&*(),.?":{}|<>]/.test(password);
}

// Signed, short-lived, one-use authorization token
function signSignupToken(payload) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', otpSecret)
    .update(encoded).digest('base64url');
  return `${encoded}.${signature}`;
}

function verifySignupToken(token) {
  if (typeof token !== 'string') return null;

  const parts = token.split('.');
  if (parts.length !== 2) return null;

  const [encoded, signature] = parts;
  const expected = crypto.createHmac('sha256', otpSecret)
    .update(encoded).digest();

  let submitted;
  try {
    submitted = Buffer.from(signature, 'base64url');
  } catch (_) {
    return null;
  }

  if (
    expected.length !== submitted.length ||
    !crypto.timingSafeEqual(expected, submitted)
  ) return null;

  try {
    const payload = JSON.parse(
      Buffer.from(encoded, 'base64url').toString('utf8')
    );

    if (
      !payload.email ||
      !payload.jti ||
      !payload.exp ||
      Date.now() > payload.exp
    ) return null;

    return payload;
  } catch (_) {
    return null;
  }
}

// =====================================
// EMAIL OTP: SEND
// =====================================
app.post('/api/send-email-otp', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();

  if (!email || !isGmail(email)) {
    return res.status(400).json({
      status: 'error',
      message: 'Please use a valid Gmail address only.'
    });
  }

  if (!transporter) {
    return res.status(503).json({
      status: 'error',
      message: 'Email OTP service is not configured.'
    });
  }

  try {
    const emailKey = Buffer.from(email).toString('base64url');
    const otpRef = db.ref(`emailOtps/${emailKey}`);
    const previous = (await otpRef.once('value')).val();

    if (
      previous &&
      previous.createdAt &&
      Date.now() - previous.createdAt < 60000
    ) {
      return res.status(429).json({
        status: 'error',
        message: 'Please wait 60 seconds before requesting another OTP.'
      });
    }

    const code = crypto.randomInt(100000, 1000000).toString();
    const now = Date.now();

    await otpRef.set({
      email,
      codeHash: hashOTP(email, code),
      used: false,
      attempts: 0,
      createdAt: now,
      expiresAt: now + (10 * 60 * 1000)
    });

    try {
      await transporter.sendMail({
        from: `"CCW Network" <${GMAIL_USER}>`,
        to: email,
        subject: 'Your CCW Network Verification Code',
        text: `Your CCW Network verification code is: ${code}

This code expires in 10 minutes. Do not share it with anyone.`,
        html: `<div style="font-family:Arial,sans-serif;padding:20px">
          <h2>CCW Network Verification</h2>
          <p>Your email verification code is:</p>
          <h1 style="letter-spacing:6px">${code}</h1>
          <p>This code expires in 10 minutes.</p>
          <p>Do not share this code with anyone.</p>
        </div>`
      });
    } catch (mailError) {
      await otpRef.remove();
      throw mailError;
    }

    return res.json({
      status: 'success',
      message: 'OTP sent successfully to your Gmail address.'
    });

  } catch (error) {
    console.error('Email OTP send error:', error.message);

    return res.status(500).json({
      status: 'error',
      message: 'Unable to send OTP. Please try again later.'
    });
  }
});

// =====================================
// EMAIL OTP: VERIFY
// =====================================
app.post('/api/verify-email-otp', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const code = String(req.body.code || '').trim();

  if (!isGmail(email) || !/^\d{6}$/.test(code)) {
    return res.status(400).json({
      status: 'error',
      message: 'Invalid Gmail address or OTP code.'
    });
  }

  try {
    const emailKey = Buffer.from(email).toString('base64url');
    const otpRef = db.ref(`emailOtps/${emailKey}`);
    const now = Date.now();

    const result = await otpRef.transaction(current => {
      if (
        !current ||
        current.used === true ||
        now > current.expiresAt ||
        (current.attempts || 0) >= 5
      ) return;

      const storedHash = Buffer.from(current.codeHash, 'hex');
      const submittedHash = Buffer.from(hashOTP(email, code), 'hex');

      const matches =
        storedHash.length === submittedHash.length &&
        crypto.timingSafeEqual(storedHash, submittedHash);

      if (!matches) {
        return {
          ...current,
          attempts: (current.attempts || 0) + 1
        };
      }

      return {
        ...current,
        used: true,
        verifiedAt: now
      };
    });

    const finalData = result.snapshot.val();

    if (
      !(
        result.committed &&
        finalData &&
        finalData.used === true &&
        finalData.verifiedAt === now
      )
    ) {
      if (!finalData) {
        return res.status(400).json({
          status: 'error',
          message: 'Invalid or expired OTP.'
        });
      }

      if (finalData.used === true) {
        return res.status(400).json({
          status: 'error',
          message: 'This OTP has already been used.'
        });
      }

      if (Date.now() > finalData.expiresAt) {
        return res.status(400).json({
          status: 'error',
          message: 'OTP has expired. Please request a new one.'
        });
      }

      if ((finalData.attempts || 0) >= 5) {
        return res.status(429).json({
          status: 'error',
          message: 'Too many incorrect attempts. Request a new OTP.'
        });
      }

      return res.status(400).json({
        status: 'error',
        message: 'Incorrect OTP code.'
      });
    }

    const jti = crypto.randomBytes(24).toString('hex');
    const expiresAt = Date.now() + (10 * 60 * 1000);

    const verificationToken = signSignupToken({
      email,
      jti,
      exp: expiresAt
    });

    await db.ref(`signupOtpTokens/${jti}`).set({
      email,
      expiresAt,
      used: false,
      createdAt: Date.now()
    });

    return res.json({
      status: 'success',
      message: 'Email OTP verified successfully!',
      email,
      verified: true,
      verificationToken
    });

  } catch (error) {
    console.error('Email OTP verification error:', error);

    return res.status(500).json({
      status: 'error',
      message: 'Internal Server Error'
    });
  }
});

// =====================================
// SECURE SIGNUP: CREATE FIREBASE USER
// ONLY AFTER OTP VERIFICATION
// =====================================
app.post('/api/signup-with-email-otp', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = req.body.password;
  const verificationToken = req.body.verificationToken;

  if (!isGmail(email) || !isStrongPassword(password)) {
    return res.status(400).json({
      status: 'error',
      message: 'Use a valid Gmail address and a password meeting all requirements.'
    });
  }

  const payload = verifySignupToken(verificationToken);

  if (!payload || payload.email !== email) {
    return res.status(401).json({
      status: 'error',
      message: 'Gmail verification expired or invalid. Please verify again.'
    });
  }

  try {
    const tokenRef = db.ref(`signupOtpTokens/${payload.jti}`);

    const consumeResult = await tokenRef.transaction(current => {
      if (
        !current ||
        current.used === true ||
        current.email !== email ||
        Date.now() > current.expiresAt
      ) return;

      return {
        ...current,
        used: true,
        usedAt: Date.now()
      };
    });

    const tokenData = consumeResult.snapshot.val();

    if (
      !consumeResult.committed ||
      !tokenData ||
      tokenData.used !== true
    ) {
      return res.status(401).json({
        status: 'error',
        message: 'This verification authorization has expired or already been used. Please verify again.'
      });
    }

    const userRecord = await admin.auth().createUser({
      email,
      password,
      emailVerified: true,
      disabled: false
    });

    const customToken = await admin.auth()
      .createCustomToken(userRecord.uid);

    return res.json({
      status: 'success',
      message: 'Gmail verified account created successfully.',
      uid: userRecord.uid,
      customToken
    });

  } catch (error) {
    console.error('Verified signup error:', error);

    if (error.code === 'auth/email-already-exists') {
      return res.status(409).json({
        status: 'error',
        message: 'This Gmail is already registered. Please sign in.'
      });
    }

    return res.status(500).json({
      status: 'error',
      message: 'Unable to create account. Please try again.'
    });
  }
});

// =====================================
// TELEGRAM BOT SETUP (EXISTING)
// =====================================
const BOT_TOKEN = process.env.BOT_TOKEN;
const CHANNEL_USERNAME = '@VerifyCryptoMining';
const bot = new Telegraf(BOT_TOKEN);

bot.start(async (ctx) => {
  const telegramUserId = ctx.from.id.toString();

  try {
    const claimedSnap = await db.ref(
      `claimedTelegramIds/${telegramUserId}`
    ).once('value');

    if (claimedSnap.val() === true) {
      return ctx.reply(
        '❌ You have already verified a task using this Telegram account!'
      );
    }

    const member = await ctx.telegram.getChatMember(
      CHANNEL_USERNAME,
      ctx.from.id
    );

    const isMember = [
      'creator',
      'administrator',
      'member'
    ].includes(member.status);

    if (!isMember) {
      return ctx.reply(
        `❌ You haven't joined our channel yet!\n\nPlease join: ${CHANNEL_USERNAME}\n\nAfter joining, click /start again.`
      );
    }

    const otpCode = crypto.randomInt(100000, 1000000).toString();
    const now = Date.now();

    await db.ref(`otps/${otpCode}`).set({
      telegramId: telegramUserId,
      used: false,
      createdAt: now,
      expiresAt: now + (10 * 60 * 1000)
    });

    return ctx.reply(
      `🔑 Your 6-digit OTP code:\n\n\`${otpCode}\`\n\n⚠️ This code can only be used once.`,
      { parse_mode: 'Markdown' }
    );

  } catch (error) {
    console.error('Error in start command:', error);

    return ctx.reply(
      '⚠️ Service error! Please try again later.'
    );
  }
});

bot.launch().catch(error => {
  console.error('Telegram bot launch error:', error);
});

// =====================================
// TELEGRAM TASK VERIFICATION (EXISTING)
// =====================================
app.post('/api/verify-task', async (req, res) => {
  const { code, userCode } = req.body;

  if (!code || !/^\d{6}$/.test(String(code)) || !userCode) {
    return res.status(400).json({
      status: 'error',
      message: 'Invalid request data!'
    });
  }

  try {
    const otpRef = db.ref(`otps/${code}`);
    const snapshot = await otpRef.once('value');
    const otpData = snapshot.val();

    if (!otpData) {
      return res.status(400).json({
        status: 'error',
        message: 'Invalid OTP Code!'
      });
    }

    if (otpData.used === true) {
      return res.status(400).json({
        status: 'error',
        message: 'This OTP code has already been used!'
      });
    }

    if (Date.now() > otpData.expiresAt) {
      return res.status(400).json({
        status: 'error',
        message: 'This OTP code has expired!'
      });
    }

    const telegramId = otpData.telegramId;

    const claimedSnap = await db.ref(
      `claimedTelegramIds/${telegramId}`
    ).once('value');

    if (claimedSnap.val() === true) {
      await otpRef.update({ used: true });

      return res.status(400).json({
        status: 'error',
        message: 'This Telegram ID has already been used!'
      });
    }

    const updates = {};

    updates[`otps/${code}/used`] = true;
    updates[`otps/${code}/usedAt`] = Date.now();
    updates[`claimedTelegramIds/${telegramId}`] = true;

    await db.ref().update(updates);

    return res.json({
      status: 'success',
      message: 'OTP verified & Telegram ID bound successfully!',
      telegramId
    });

  } catch (error) {
    console.error('Error verifying OTP:', error);

    return res.status(500).json({
      status: 'error',
      message: 'Internal Server Error'
    });
  }
});

// =====================================
// SERVER
// =====================================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Verification Server running on port ${PORT}`);
});

process.once('SIGINT', () => bot.stop('SIGINT'));
process.once('SIGTERM', () => bot.stop('SIGTERM'));
