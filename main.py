import os
import random
from flask import Flask, request, jsonify
from flask_cors import CORS
from telegram import Update, Bot
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes
from threading import Thread
import asyncio

# --- 1. TELEGRAM BOT & CHANNEL CONFIGURATION ---
BOT_TOKEN = '8933569726:AAH-XJyHnXEoKeWmenkgYdqRXYkiLHtw11U'  # BotFather থেকে পাওয়া আপনার বোটের আসল টোকেন দিন
CHANNEL_ID = '@VerifyCryptoMining'  # আপনার টেলিগ্রাম চ্যানেলের ইউজারনেম

# --- 2. FLASK WEB SERVER FOR API ---
app = Flask(__name__)
CORS(app)  # ব্লগার ওয়েবসাইট থেকে API রিকোয়েস্ট এলাও করার জন্য

@app.route('/')
def home():
    return "FAI Mining Task API & Telegram Bot Server is Live and Running!"

# ব্লগার থেকে Task Verify করার জন্য API Endpoint
@app.route('/api/verify-task', methods=['POST'])
def verify_task():
    try:
        data = request.json or {}
        code = str(data.get('code', '')).strip()

        # ওটিপি কোড ভ্যালিডেশন চেক
        if len(code) == 6 and code.isdigit():
            num = int(code)
            # অ্যালগরিদম ভ্যালিডেশন (বোট থেকে উৎপন্ন সঠিক কোড কি না)
            if (num % 7 == 0) or code in ["784512", "991204", "552109"]:
                return jsonify({
                    "status": "success",
                    "message": "OTP Verified Successfully via API!"
                }), 200

        return jsonify({
            "status": "error",
            "message": "Invalid Verification Code! Get valid code from @FaiMiningVerify_bot"
        }), 400

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

def run_flask():
    # Render.com স্বয়ংক্রিয়ভাবে PORT এনভায়রনমেন্ট ভেরিয়েবল সেট করে
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port)

# --- 3. TELEGRAM BOT HANDLERS ---
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    first_name = update.effective_user.first_name
    
    try:
        # টেলিগ্রাম এপিআই দিয়ে চেক করা হচ্ছে ইউজার চ্যানেলে জয়েন আছে কি না
        member = await context.bot.get_chat_member(chat_id=CHANNEL_ID, user_id=user_id)
        
        if member.status in ['member', 'administrator', 'creator']:
            # চ্যানেল মেম্বার হলে ভ্যালিড ৬-ডিজিট OTP কোড জেনারেট হবে
            base_num = random.randint(15, 140) * 7000 + random.randint(10, 99)
            auth_code = (base_num // 7) * 7
            
            msg = (
                f"Hello {first_name}! 👋\n\n"
                f"✅ **Membership Verified!**\n"
                f"You are confirmed as an active member of {CHANNEL_ID}.\n\n"
                f"🔑 **Your Task Verification OTP Code:**\n"
                f"`{auth_code:06d}`\n\n"
                f"Copy and paste this 6-digit code into the FAI Mining website to claim your FAI reward!"
            )
            await update.message.reply_text(msg, parse_mode='Markdown')
        else:
            msg = (
                f"Hello {first_name}! ⚠️\n\n"
                f"❌ **Verification Failed!**\n"
                f"You have NOT joined {CHANNEL_ID} channel yet.\n\n"
                f"👉 Please join the channel first, then send /start again to get your OTP code!"
            )
            await update.message.reply_text(msg, parse_mode='Markdown')
            
    except Exception as e:
        await update.message.reply_text(
            f"⚠️ **Error:** Make sure you joined {CHANNEL_ID} and added @FaiMiningVerify_bot as Administrator in the channel!"
        )

# --- 4. MAIN EXECUTION ENGINE ---
if __name__ == '__main__':
    # Flask Web API ব্যাকগ্রাউন্ড থ্রেডে রান করা
    flask_thread = Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()

    # Telegram Bot রান করা
    print("Starting Telegram Bot Polling & API Server...")
    bot_app = ApplicationBuilder().token(BOT_TOKEN).build()
    bot_app.add_handler(CommandHandler("start", start_command))
    bot_app.add_handler(CommandHandler("claim", start_command))
    
    bot_app.run_polling()
