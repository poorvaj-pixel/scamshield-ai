import os
import re
import json
from urllib.parse import urlparse

from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv

# Optional Gemini AI
try:
    from openai import OpenAI
except ImportError:
    genai = None


# --------------------------------------------------
# APP SETUP
# --------------------------------------------------

load_dotenv()

app = Flask(__name__)
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

openai_client = None

if OPENAI_API_KEY:
    try:
        openai_client = OpenAI(api_key=OPENAI_API_KEY)
        print("OpenAI client initialized successfully.")
    except Exception as error:
        print("OpenAI initialization error:", error)
        openai_client = None
# --------------------------------------------------
# SCAM PATTERNS
# --------------------------------------------------

PATTERNS = {
    "urgency": {
        "keywords": [
            "urgent",
            "immediately",
            "act now",
            "within 24 hours",
            "expires today",
            "last chance",
            "hurry",
            "verify now",
            "account will be blocked",
            "account will be suspended"
        ],
        "weight": 12
    },

    "financial": {
        "keywords": [
            "send money",
            "transfer money",
            "payment",
            "pay now",
            "refund",
            "bank account",
            "credit card",
            "debit card",
            "upi",
            "otp",
            "transaction",
            "cash",
            "prize money"
        ],
        "weight": 15
    },

    "credentials": {
        "keywords": [
            "password",
            "username",
            "login",
            "sign in",
            "verify your identity",
            "verification",
            "otp",
            "pin",
            "cvv",
            "account details"
        ],
        "weight": 18
    },

    "reward": {
        "keywords": [
            "you won",
            "winner",
            "congratulations",
            "lottery",
            "free gift",
            "reward",
            "cash prize",
            "lucky winner",
            "claim your prize"
        ],
        "weight": 15
    },

    "threat": {
        "keywords": [
            "legal action",
            "police",
            "arrest",
            "penalty",
            "fine",
            "blocked",
            "suspended",
            "court case"
        ],
        "weight": 16
    },

    "impersonation": {
        "keywords": [
            "bank manager",
            "customer care",
            "government",
            "police officer",
            "income tax",
            "delivery agent",
            "support team",
            "official notice"
        ],
        "weight": 12
    },

    "job_scam": {
        "keywords": [
            "work from home",
            "easy money",
            "earn daily",
            "registration fee",
            "processing fee",
            "job offer",
            "guaranteed income",
            "pay to join",
            "investment required"
        ],
        "weight": 14
    }
}


# --------------------------------------------------
# URL DETECTION
# --------------------------------------------------

def extract_urls(text):
    pattern = r'https?://[^\s]+|www\.[^\s]+'
    return re.findall(pattern, text, re.IGNORECASE)


def analyze_url(url):

    score = 0
    reasons = []

    clean_url = url.rstrip(".,!?;:")

    if not clean_url.startswith(("http://", "https://")):
        clean_url = "http://" + clean_url

    try:
        parsed = urlparse(clean_url)
        hostname = parsed.hostname or ""
        full_url = clean_url.lower()

        # IP address instead of domain
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
            score += 25
            reasons.append("The link uses an IP address instead of a normal domain.")

        # Very long URL
        if len(clean_url) > 100:
            score += 10
            reasons.append("The URL is unusually long.")

        # @ symbol
        if "@" in clean_url:
            score += 20
            reasons.append("The URL contains an @ symbol, which can hide the real destination.")

        # Punycode
        if "xn--" in hostname:
            score += 20
            reasons.append("The domain uses punycode, which can sometimes be used for look-alike domains.")

        # Too many subdomains
        if hostname.count(".") >= 4:
            score += 10
            reasons.append("The domain contains an unusually large number of subdomains.")

        # Suspicious URL words
        suspicious_words = [
            "verify",
            "login",
            "secure",
            "account",
            "update",
            "claim",
            "reward",
            "free",
            "gift",
            "winner",
            "urgent"
        ]

        found_words = [
            word for word in suspicious_words
            if word in full_url
        ]

        if found_words:
            score += min(len(found_words) * 4, 16)
            reasons.append(
                "The URL contains suspicious terms: "
                + ", ".join(found_words[:5])
            )

        # Common URL shorteners
        shorteners = [
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "is.gd",
            "cutt.ly",
            "shorturl.at"
        ]

        if hostname.lower() in shorteners:
            score += 15
            reasons.append("The link uses a URL-shortening service.")

    except Exception:
        score += 10
        reasons.append("The URL could not be fully parsed.")

    return min(score, 40), reasons


# --------------------------------------------------
# TEXT ANALYSIS
# --------------------------------------------------

def analyze_text(text):

    text_lower = text.lower()

    score = 0
    reasons = []
    signals = {
        "urgency": 0,
        "financial": 0,
        "credentials": 0,
        "reward": 0,
        "threat": 0,
        "impersonation": 0,
        "job_scam": 0,
        "url": 0
    }

    for category, data in PATTERNS.items():

        matches = []

        for keyword in data["keywords"]:
            if keyword in text_lower:
                matches.append(keyword)

        if matches:

            category_score = min(
                len(matches) * data["weight"],
                30
            )

            score += category_score
            signals[category] = category_score

            reasons.append(
                f"{category.replace('_', ' ').title()} signals detected: "
                + ", ".join(matches[:4])
            )

    # Excessive capital letters
    letters = [c for c in text if c.isalpha()]

    if letters:

        uppercase = sum(1 for c in letters if c.isupper())
        uppercase_ratio = uppercase / len(letters)

        if uppercase_ratio > 0.55 and len(letters) > 15:
            score += 8
            reasons.append("The message uses unusually high capitalization.")

    # Excessive exclamation marks
    if text.count("!") >= 3:
        score += 6
        reasons.append("The message uses repeated exclamation marks.")

    return min(score, 70), signals, reasons

def detect_scam_category(text, reasons):
    text_lower = text.lower()

    categories = {
        "Banking Phishing": [
            "bank", "account", "otp", "upi", "transaction",
            "debit card", "credit card", "net banking"
        ],
        "Job Scam": [
            "job", "work from home", "salary", "hiring",
            "vacancy", "recruitment", "registration fee"
        ],
        "Shopping Scam": [
            "order", "delivery", "shopping", "discount",
            "offer", "refund", "coupon"
        ],
        "Investment Scam": [
            "investment", "profit", "trading", "crypto",
            "returns", "stock", "double your money"
        ],
        "Impersonation": [
            "official", "police", "government", "support",
            "customer care", "verify your identity"
        ],
        "Phishing": [
            "click here", "verify", "login", "password",
            "security alert", "suspended"
        ]
    }

    scores = {}

    for category, keywords in categories.items():
        scores[category] = sum(
            1 for keyword in keywords
            if keyword in text_lower
        )

    best_category = max(scores, key=scores.get)

    if scores[best_category] == 0:
        return "General Scam"

    return best_category

# --------------------------------------------------
# RISK LEVEL
# --------------------------------------------------

def get_risk_level(score):

    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 35:
        return "MEDIUM"

    return "LOW"


# --------------------------------------------------
# LOCAL SCAM ANALYSIS
# --------------------------------------------------

def local_analysis(text):

    text_score, signals, reasons = analyze_text(text)

    urls = extract_urls(text)

    url_score = 0
    url_reasons = []

    for url in urls:
        individual_score, individual_reasons = analyze_url(url)

        url_score += individual_score
        url_reasons.extend(individual_reasons)

    url_score = min(url_score, 40)

    signals["url"] = url_score

    reasons.extend(url_reasons)

    # Combine scores
    total_score = min(
        text_score + url_score,
        100
    )

    risk_level = get_risk_level(total_score)

    if risk_level == "CRITICAL":
        recommendation = (
            "Do not click links, share OTPs, passwords, banking details, "
            "or send money. Verify the message using an official channel."
        )

    elif risk_level == "HIGH":
        recommendation = (
            "Do not interact with the message until you independently "
            "verify the sender and website."
        )

    elif risk_level == "MEDIUM":
        recommendation = (
            "Be cautious. Verify the sender, links, and requested action "
            "before responding."
        )

    else:
        recommendation = (
            "No strong scam indicators were detected, but always verify "
            "unexpected requests independently."
        )

    if not reasons:
        reasons.append("No strong suspicious patterns were detected.")
    category = detect_scam_category(text, reasons)
    return {
        "risk_score": total_score,
        "risk_level": risk_level,
        "signals": signals,
        "category": category,
        "reasons": reasons,
        "urls_found": urls,
        "recommendation": recommendation
    }


# --------------------------------------------------
# GEMINI AI ANALYSIS
# --------------------------------------------------

def ai_analysis(text, local_result):

    risk_score = local_result["risk_score"]
    risk_level = local_result["risk_level"]
    reasons = local_result["reasons"]

    # If OpenAI is available, try AI analysis first
    if openai_client:

        prompt = f"""
You are ScamShield AI, a cybersecurity safety assistant.

Analyze this message for scam, phishing, and social-engineering indicators.

MESSAGE:
{text}

LOCAL ANALYSIS:
Risk score: {risk_score}
Risk level: {risk_level}
Reasons: {reasons}

Return ONLY valid JSON:

{{
  "summary": "short explanation",
  "threats": ["threat 1", "threat 2"],
  "actions": ["safe action 1", "safe action 2"],
  "confidence": 0
}}

Do not invent facts.
Do not tell the user to click suspicious links.
Focus on safe verification.
"""

        try:

            response = openai_client.responses.create(
                model="gpt-5.6-luna",
                input=prompt
            )

            result_text = response.output_text.strip()

            result_text = re.sub(
                r"^```json\s*|\s*```$",
                "",
                result_text,
                flags=re.IGNORECASE
            )

            parsed = json.loads(result_text)

            parsed["available"] = True

            return parsed

        except Exception as error:

            print("OPENAI API ERROR:", error)

    # Local fallback analysis
    if risk_level == "CRITICAL":

        summary = (
            "This message contains multiple strong indicators of a "
            "potential scam or phishing attempt. Immediate caution is recommended."
        )

    elif risk_level == "HIGH":

        summary = (
            "This message contains several suspicious patterns commonly "
            "associated with scams or phishing attempts."
        )

    elif risk_level == "MEDIUM":

        summary = (
            "This message contains some potentially suspicious patterns. "
            "Verify the sender and information independently before taking action."
        )

    else:

        summary = (
            "No major scam indicators were detected by the current local "
            "analysis. Still verify unexpected messages before sharing information."
        )

    threats = reasons[:4]

    actions = [
        "Do not click suspicious links.",
        "Do not share passwords, OTPs, PINs, or banking details.",
        "Verify the sender through an official website or trusted contact method."
    ]

    return {
        "available": True,
        "summary": summary,
        "threats": threats,
        "actions": actions,
        "confidence": min(95, max(50, risk_score))
    }
        
# --------------------------------------------------
# HOME PAGE
# --------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html")


# --------------------------------------------------
# ANALYZE API
# --------------------------------------------------

@app.route("/api/analyze", methods=["POST"])
def analyze():

    try:

        data = request.get_json()

        if not data:
            return jsonify({
                "error": "No data received."
            }), 400

        message = data.get("message", "").strip()

        if not message:
            return jsonify({
                "error": "Please enter a message to analyze."
            }), 400

        if len(message) > 10000:
            return jsonify({
                "error": "Message is too long. Please keep it under 10,000 characters."
            }), 400

        # Local analysis
        result = local_analysis(message)

        # AI analysis
        ai_result = ai_analysis(
            message,
            result
        )

        result["ai_analysis"] = ai_result

        return jsonify(result)

    except Exception as error:

        return jsonify({
            "error": "Something went wrong during analysis.",
            "details": str(error)
        }), 500


# --------------------------------------------------
# HEALTH CHECK
# --------------------------------------------------

@app.route("/api/health")
def health():

    return jsonify({
        "status": "online",
        "python_ai": gemini_client is not None
    })


# --------------------------------------------------
# RUN APPLICATION
# --------------------------------------------------

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            5000
        )
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=True
    )