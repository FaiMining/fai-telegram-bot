
const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const { Telegraf } = require('telegraf');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();

app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));
app.use(cors());

// =====================================
// CONFIGURATION
// =====================================
const PORT = Number(process.env.PORT) || 3000;
const DATABASE_URL = 'https://fai-mining-app-default-rtdb.firebaseio.com';

let serviceAccount;

try {
  if (!process.env.FIREBASE_SERVICE_ACCOUNT) {
    throw new Error('FIREBASE_SERVICE_ACCOUNT is missing.');
  }

  serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

  if (
    !serviceAccount ||
    !serviceAccount.project_id ||
    !serviceAccount.private_key ||
    !serviceAccount.client_email
  ) {
    throw new Error('Firebase service account fields are missing.');
  }
} catch (error) {
  console.error('Firebase configuration error:', error.message);
  process.exit(1);
}

try {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: DATABASE_URL
  });
} catch (error) {
  console.error('Firebase initialization error:', error.message);
  process.exit(1);
}

const db = admin.database();

// =====================================
// EMAIL CONFIGURATION
// =====================================
const GMAIL_USER = (process.env.GMAIL_USER || '').trim();
const GMAIL_APP_PASSWORD =
  (process.env.GMAIL_APP_PASSWORD || '').replace(/\s/g, '');

const OTP_EMAIL_ENABLED =
  String(process.env.OTP_EMAIL_ENABLED || '').trim().toLowerCase() === 'true';

const otpSecret =
  process.env.OTP_HASH_SECRET || serviceAccount.private_key;

if (!process.env.OTP_HASH_SECRET) {
  console.warn(
    'WARNING: OTP_HASH_SECRET is missing. Set a long random secret in Render.'
  );
}

let transporter = null;

if (OTP_EMAIL_ENABLED && GMAIL_USER && GMAIL_APP_PASSWORD) {
  transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,

    auth: {
      user: GMAIL_USER,
      pass: GMAIL_APP_PASSWORD
    },

    connectionTimeout: 15000,
    greetingTimeout: 15000,
    socketTimeout: 20000,

    tls: {
      minVersion: 'TLSv1.2'
    }
  });

  transporter.verify()
    .then(() => {
      console.log('Gmail SMTP connection verified successfully.');
    })
    .catch(error => {
      console.error(
        'Gmail SMTP connection failed:',
        error.message
      );
    });

} else {
  console.warn(
    'Email OTP disabled or Gmail configuration missing. Check OTP_EMAIL_ENABLED, GMAIL_USER and GMAIL_APP_PASSWORD.'
  );
}

// =====================================
// TIMEOUT HELPER
// =====================================
function withTimeout(promise, ms, label) {
  let timer;

  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      const error = new Error(`${label} timed out after ${ms}ms`);
      error.code = 'UPSTREAM_TIMEOUT';
      reject(error);
    }, ms);
  });

  return Promise.race([promise, timeout])
    .finally(() => clearTimeout(timer));
}

// =====================================
// HELPER FUNCTIONS
// =====================================
function hashOTP(email, code) {
  return crypto.createHmac('sha256', otpSecret)
    .update(`${email}:${code}`)
    .digest('hex');
}

function isGmail(email) {
  return typeof email === 'string' &&
    /^[a-zA-Z0-9._%+-]+@gmail\.com$/i.test(email);
}

function isStrongPassword(password) {
  return typeof password === 'string' &&
    password.length >= 8 &&
    /[A-Z]/.test(password) &&
    /[a-z]/.test(password) &&
    /[0-9]/.test(password) &&
    /[!@#$%^&*(),.?":{}|<>]/.test(password);
}

function emailKeyFor(email) {
  return Buffer.from(email, 'utf8').toString('base64url');
}

// =====================================
// SIGNUP TOKEN
// =====================================
function signSignupToken(payload) {
  const encoded = Buffer.from(
    JSON.stringify(payload)
  ).toString('base64url');

  const signature = crypto.createHmac('sha256', otpSecret)
    .update(encoded)
    .digest('base64url');

  return `${encoded}.${signature}`;
}

function verifySignupToken(token) {
  if (typeof token !== 'string') return null;

  const parts = token.split('.');

  if (parts.length !== 2) return null;

  const [encoded, signature] = parts;

  const expected = crypto.createHmac('sha256', otpSecret)
    .update(encoded)
    .digest();

  let submitted;

  try {
    submitted = Buffer.from(signature, 'base64url');
  } catch (_) {
    return null;
  }

  if (
    expected.length !== submitted.length ||
    !crypto.timingSafeEqual(expected, submitted)
  ) {
    return null;
  }

  try {
    const payload = JSON.parse(
      Buffer.from(encoded, 'base64url').toString('utf8')
    );

    if (
      !payload ||
      typeof payload.email !== 'string' ||
      typeof payload.jti !== 'string' ||
      !Number.isFinite(payload.exp) ||
      Date.now() > payload.exp
    ) {
      return null;
    }

    return payload;

  } catch (_) {
    return null;
  }
}

// =====================================
// HEALTH CHECK
// =====================================
app.get('/', (_req, res) => {
  res.status(200).json({
    status: 'ok',
    service: 'CCW Network Verification API',
    emailOtpEnabled: Boolean(transporter)
  });
});

app.get('/api/health', (_req, res) => {
  res.status(200).json({
    status: 'ok',
    emailOtpConfigured: Boolean(transporter)
  });
});

// =====================================
// EMAIL OTP: SEND
// =====================================
app.post('/api/send-email-otp', async (req, res) => {
  const email = String(
    (req.body && req.body.email) || ''
  ).trim().toLowerCase();

  if (!email || !isGmail(email)) {
    return res.status(400).json({
      status: 'error',
      message: 'Please use a valid Gmail address only.'
    });
  }

  if (!transporter) {
    return res.status(503).json({
      status: 'error',
      message: 'Email OTP service is not configured. Please contact support.'
    });
  }

  const otpRef = db.ref(
    `emailOtps/${emailKeyFor(email)}`
  );

  try {
    // Check previous OTP
    const previous = (
      await withTimeout(
        otpRef.once('value'),
        12000,
        'Firebase OTP lookup'
      )
    ).val();

    if (
      previous &&
      Number.isFinite(previous.createdAt) &&
      Date.now() - previous.createdAt < 60000
    ) {
      return res.status(429).json({
        status: 'error',
        message: 'Please wait 60 seconds before requesting another OTP.'
      });
    }

    // Generate OTP
    const code = crypto.randomInt(
      100000,
      1000000
    ).toString();

    const now = Date.now();

    // Save hashed OTP
    await withTimeout(
      otpRef.set({
        email,
        codeHash: hashOTP(email, code),
        used: false,
        attempts: 0,
        createdAt: now,
        expiresAt: now + (10 * 60 * 1000)
      }),
      12000,
      'Firebase OTP save'
    );

    // Send email
    try {
      await withTimeout(
        transporter.sendMail({
          from: `"CCW Network" <${GMAIL_USER}>`,
          to: email,
          subject: 'Your CCW Network Verification Code',

          text: `Your CCW Network verification code is: ${code}

This code expires in 10 minutes. Do not share it with anyone.`,

          html: `
            <div style="font-family:Arial,sans-serif;padding:20px">
              <h2>CCW Network Verification</h2>
              <p>Your email verification code is:</p>
              <h1 style="letter-spacing:6px">${code}</h1>
              <p>This code expires in 10 minutes.</p>
              <p>Do not share this code with anyone.</p>
            </div>
          `
        }),
        25000,
        'Gmail SMTP send'
      );

    } catch (mailError) {
      try {
        await withTimeout(
          otpRef.remove(),
          8000,
          'Firebase OTP cleanup'
        );
      } catch (cleanupError) {
        console.error(
          'OTP cleanup failed:',
          cleanupError.message
        );
      }

      throw mailError;
    }

    return res.status(200).json({
      status: 'success',
      message: 'OTP sent successfully to your Gmail address.'
    });

  } catch (error) {
    console.error(
      'Email OTP send failed:',
      error.code || '',
      error.message || error
    );

    if (error.code === 'UPSTREAM_TIMEOUT') {
      return res.status(504).json({
        status: 'error',
        message: 'The OTP service took too long to respond. Please try again shortly.'
      });
    }

    return res.status(500).json({
      status: 'error',
      message: 'Unable to send OTP. Check server logs and email configuration.'
    });
  }
});

// =====================================
// EMAIL OTP: VERIFY
// =====================================
app.post('/api/verify-email-otp', async (req, res) => {
  const email = String(
    (req.body && req.body.email) || ''
  ).trim().toLowerCase();

  const code = String(
    (req.body && req.body.code) || ''
  ).trim();

  if (!isGmail(email) || !/^\d{6}$/.test(code)) {
    return res.status(400).json({
      status: 'error',
      message: 'Invalid Gmail address or OTP code.'
    });
  }

  try {
    const otpRef = db.ref(
      `emailOtps/${emailKeyFor(email)}`
    );

    const now = Date.now();

    const result = await withTimeout(
      otpRef.transaction(current => {
        if (
          !current ||
          current.used === true ||
          !Number.isFinite(current.expiresAt) ||
          now > current.expiresAt ||
          (current.attempts || 0) >= 5
        ) {
          return;
        }

        const storedHash = Buffer.from(
          current.codeHash || '',
          'hex'
        );

        const submittedHash = Buffer.from(
          hashOTP(email, code),
          'hex'
        );

        const matches =
          storedHash.length > 0 &&
          storedHash.length === submittedHash.length &&
          crypto.timingSafeEqual(
            storedHash,
            submittedHash
          );

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
      }),
      12000,
      'Firebase OTP verification'
    );

    const finalData = result.snapshot.val();

    if (!(
      result.committed &&
      finalData &&
      finalData.used === true &&
      finalData.verifiedAt === now
    )) {

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

      if (
        !Number.isFinite(finalData.expiresAt) ||
        Date.now() > finalData.expiresAt
      ) {
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

    // Create one-use signup authorization
    const jti = crypto.randomBytes(24).toString('hex');

    const expiresAt = Date.now() + (10 * 60 * 1000);

    const verificationToken = signSignupToken({
      email,
      jti,
      exp: expiresAt
    });

    await withTimeout(
      db.ref(`signupOtpTokens/${jti}`).set({
        email,
        expiresAt,
        used: false,
        createdAt: Date.now()
      }),
      12000,
      'Firebase signup-token save'
    );

    return res.status(200).json({
      status: 'success',
      message: 'Email OTP verified successfully!',
      email,
      verified: true,
      verificationToken
    });

  } catch (error) {
    console.error(
      'Email OTP verification failed:',
      error.code || '',
      error.message || error
    );

    if (error.code === 'UPSTREAM_TIMEOUT') {
      return res.status(504).json({
        status: 'error',
        message: 'Verification service timed out. Please try again shortly.'
      });
    }

    return res.status(500).json({
      status: 'error',
      message: 'Internal server error while verifying OTP.'
    });
  }
});

// =====================================
// SECURE SIGNUP
// CREATE FIREBASE USER AFTER OTP
// =====================================
app.post('/api/signup-with-email-otp', async (req, res) => {
  const email = String(
    (req.body && req.body.email) || ''
  ).trim().toLowerCase();

  const password = req.body && req.body.password;

  const verificationToken =
    req.body && req.body.verificationToken;

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
    const tokenRef = db.ref(
      `signupOtpTokens/${payload.jti}`
    );

    const consumeResult = await withTimeout(
      tokenRef.transaction(current => {
        if (
          !current ||
          current.used === true ||
          current.email !== email ||
          Date.now() > current.expiresAt
        ) {
          return;
        }

        return {
          ...current,
          used: true,
          usedAt: Date.now()
        };
      }),
      12000,
      'Firebase signup-token consumption'
    );

    const tokenData = consumeResult.snapshot.val();

    if (
      !consumeResult.committed ||
      !tokenData ||
      tokenData.used !== true ||
      tokenData.email !== email
    ) {
      return res.status(401).json({
        status: 'error',
        message: 'This verification authorization has expired or already been used. Please verify again.'
      });
    }

    const userRecord = await withTimeout(
      admin.auth().createUser({
        email,
        password,
        emailVerified: true,
        disabled: false
      }),
      15000,
      'Firebase user creation'
    );

    const customToken = await withTimeout(
      admin.auth().createCustomToken(userRecord.uid),
      15000,
      'Firebase custom-token creation'
    );

    return res.status(200).json({
      status: 'success',
      message: 'Gmail verified account created successfully.',
      uid: userRecord.uid,
      customToken
    });

  } catch (error) {
    console.error(
      'Verified signup failed:',
      error.code || '',
      error.message || error
    );

    if (error.code === 'auth/email-already-exists') {
      return res.status(409).json({
        status: 'error',
        message: 'This Gmail is already registered. Please sign in.'
      });
    }

    if (error.code === 'UPSTREAM_TIMEOUT') {
      return res.status(504).json({
        status: 'error',
        message: 'Account service timed out. Please try again shortly.'
      });
    }

    return res.status(500).json({
      status: 'error',
      message: 'Unable to create account. Please try again.'
    });
  }
});

// =====================================
// TELEGRAM BOT
// =====================================
const BOT_TOKEN = process.env.BOT_TOKEN;
const CHANNEL_USERNAME = '@VerifyCryptoMining';

let bot = null;

if (BOT_TOKEN) {
  bot = new Telegraf(BOT_TOKEN);

  bot.start(async (ctx) => {
    const telegramUserId = String(ctx.from.id);

    try {
      const claimedSnap = await withTimeout(
        db.ref(
          `claimedTelegramIds/${telegramUserId}`
        ).once('value'),
        12000,
        'Firebase Telegram claim lookup'
      );

      if (claimedSnap.val() === true) {
        return ctx.reply(
          '❌ You have already verified a task using this Telegram account!'
        );
      }

      const member = await withTimeout(
        ctx.telegram.getChatMember(
          CHANNEL_USERNAME,
          ctx.from.id
        ),
        15000,
        'Telegram membership check'
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

      const otpCode = crypto.randomInt(
        100000,
        1000000
      ).toString();

      const now = Date.now();

      await withTimeout(
        db.ref(`otps/${otpCode}`).set({
          telegramId: telegramUserId,
          used: false,
          createdAt: now,
          expiresAt: now + (10 * 60 * 1000)
        }),
        12000,
        'Firebase Telegram OTP save'
      );

      return ctx.reply(
        `🔑 Your 6-digit OTP code:\n\n\`${otpCode}\`\n\n⚠️ This code can only be used once.`,
        { parse_mode: 'Markdown' }
      );

    } catch (error) {
      console.error(
        'Telegram /start error:',
        error.code || '',
        error.message || error
      );

      return ctx.reply(
        '⚠️ Service error! Please try again later.'
      );
    }
  });

  bot.launch()
    .then(() => {
      console.log('Telegram bot launched successfully.');
    })
    .catch(error => {
      console.error(
        'Telegram bot launch failed:',
        error.message
      );
    });

} else {
  console.warn(
    'BOT_TOKEN is missing. Telegram bot is disabled; HTTP API can still run.'
  );
}

// =====================================
// TELEGRAM TASK VERIFICATION
// =====================================
app.post('/api/verify-task', async (req, res) => {
  const code = String(
    (req.body && req.body.code) || ''
  ).trim();

  const userCode = req.body && req.body.userCode;

  if (!/^\d{6}$/.test(code) || !userCode) {
    return res.status(400).json({
      status: 'error',
      message: 'Invalid request data!'
    });
  }

  try {
    const otpRef = db.ref(`otps/${code}`);

    const snapshot = await withTimeout(
      otpRef.once('value'),
      12000,
      'Firebase Telegram OTP lookup'
    );

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

    const telegramId = String(otpData.telegramId);

    const claimedSnap = await withTimeout(
      db.ref(
        `claimedTelegramIds/${telegramId}`
      ).once('value'),
      12000,
      'Firebase Telegram claim lookup'
    );

    if (claimedSnap.val() === true) {
      await withTimeout(
        otpRef.update({ used: true }),
        12000,
        'Firebase OTP update'
      );

      return res.status(400).json({
        status: 'error',
        message: 'This Telegram ID has already been used!'
      });
    }

    const updates = {};

    updates[`otps/${code}/used`] = true;
    updates[`otps/${code}/usedAt`] = Date.now();

    updates[
      `claimedTelegramIds/${telegramId}`
    ] = true;

    await withTimeout(
      db.ref().update(updates),
      12000,
      'Firebase Telegram claim update'
    );

    return res.status(200).json({
      status: 'success',
      message: 'OTP verified & Telegram ID bound successfully!',
      telegramId
    });

  } catch (error) {
    console.error(
      'Telegram task verification error:',
      error.code || '',
      error.message || error
    );

    if (error.code === 'UPSTREAM_TIMEOUT') {
      return res.status(504).json({
        status: 'error',
        message: 'Verification service timed out. Please try again shortly.'
      });
    }

    return res.status(500).json({
      status: 'error',
      message: 'Internal server error.'
    });
  }
});

// =====================================
// SERVER
// =====================================
const server = app.listen(PORT, () => {
  console.log(
    `Verification Server running on port ${PORT}`
  );
});

server.requestTimeout = 30000;
server.headersTimeout = 35000;
server.keepAliveTimeout = 5000;

// =====================================
// GRACEFUL SHUTDOWN
// =====================================
function shutdown(signal) {
  console.log(`${signal} received. Shutting down.`);

  server.close(() => {
    if (bot) {
      bot.stop(signal);
    }

    admin.app().delete()
      .catch(() => {});

    process.exit(0);
  });

  setTimeout(() => {
    process.exit(1);
  }, 10000).unref();
}

process.once('SIGINT', () => shutdown('SIGINT'));
process.once('SIGTERM', () => shutdown('SIGTERM'));
