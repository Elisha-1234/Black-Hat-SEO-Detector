from flask import Flask, request, render_template, jsonify
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup
import pickle
import whois
from urllib.parse import urlparse
from datetime import datetime
import google.generativeai as genai
import re  
import os                         # OS module to access environment variables
from dotenv import load_dotenv    # Module to load variables from the .env file

# Load secure environment variables from the .env file
load_dotenv()

app = Flask(__name__)
CORS(app)

# --- GEMINI AI CONFIGURATION ---
# Securely retrieve the Gemini API key from environment variables
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY") 

try:
    if GEMINI_API_KEY:
        genai.configure(api_key=GEMINI_API_KEY)
        gemini_model = genai.GenerativeModel('gemini-2.5-flash')
    else:
        gemini_model = None
except:
    gemini_model = None

# --- LOAD LOCAL ML MODEL ---
try:
    with open('models/blackhat_model.pkl', 'rb') as f:
        ai_model = pickle.load(f)
    with open('models/tfidf_vectorizer.pkl', 'rb') as f:
        vectorizer = pickle.load(f)
    AI_ENABLED = True
except Exception as e:
    AI_ENABLED = False

SPAM_WORDS = ['casino', 'hack', 'free money', 'carding', 'lottery', 'phishing', 'followers']

def categorize_website(text_content):
    text = text_content.lower()
    
    def contains_any(word_list):
        pattern = r'\b(?:' + '|'.join(word_list) + r')\b'
        return bool(re.search(pattern, text))

    if contains_any(['cart', 'checkout', 'buy now', 'shop', 'e-commerce']):
        return "E-Commerce / Shopping 🛒", "Beware of fake reviews, counterfeit products, and unsecure payment gateways."
    elif contains_any(['casino', 'bet', 'lottery', 'gamble', 'jackpot']):
        return "Gambling & Betting 🎲", "Watch out for rigged odds, hidden withdrawal rules, and unlicensed operators."
    elif contains_any(['game', 'play', 'arcade', 'esports', 'multiplayer']):
        return "Gaming & Entertainment 🎮", "Be cautious of fake in-game currency generators, phishing login pages."
    elif contains_any(['bank', 'crypto', 'wallet', 'invest', 'finance']):
        return "Financial & Crypto 🏦", "High risk of phishing scams, fake investment schemes. Double-check URLs."
    else:
        return "General / Blog / Info 🌐", "General scams like phishing links, deceptive ads can occur here."

def generate_ai_summary(text_content, final_status):
    # Generate an AI summary only if the Gemini API key is successfully configured
    if GEMINI_API_KEY and gemini_model:
        try:
            short_text = text_content[:1500] 
            prompt = f"You are a Cyber Security Expert. Analyze this website text and provide a 2-sentence threat intelligence summary. The system flagged it as: {final_status}. Text: {short_text}"
            response = gemini_model.generate_content(prompt)
            return response.text
        except:
            pass
            
    if "Critical" in final_status:
        return "Based on heuristic patterns, this domain exhibits severe black-hat traits and potential phishing indicators. Immediate caution is advised."
    elif "Suspicious" in final_status:
        return "The site utilizes questionable SEO tactics or hidden elements. Verify authenticity before sharing sensitive data."
    else:
        return "The page structure appears clean and follows standard organic guidelines without obvious malicious patterns."

def scan_url(url):
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer': 'https://www.google.com/'
        }
        response = requests.get(url, headers=headers, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        score = 0
        report_data = []
        text_content = soup.get_text()

        category, scam_advice = categorize_website(text_content)

        hidden_spam = soup.find_all(class_='hidden-spam') or soup.find_all(class_='amazon-hidden-seo')
        if hidden_spam:
            score += 30
            report_data.append({"module": "CSS Cloaking", "status": "Failed 🚩", "analysis": "Critical: Invisible spam text detected."})
        else:
            report_data.append({"module": "CSS Cloaking", "status": "Passed ✅", "analysis": "No hidden text (cloaking) detected."})

        spam_count = sum(1 for word in SPAM_WORDS if word in text_content.lower())
        if spam_count >= 2:
            score += 20
            report_data.append({"module": "Keyword Stuffing", "status": "Failed 🚩", "analysis": f"High density: Found {spam_count} black-hat keywords."})
        else:
            report_data.append({"module": "Keyword Stuffing", "status": "Passed ✅", "analysis": "Keyword density is normal."})

        meta_tag = soup.find('meta', attrs={'name': 'keywords'})
        meta_content = meta_tag.get('content', '').lower() if meta_tag else ""
        if sum(1 for word in SPAM_WORDS if word in meta_content) >= 3:
            score += 20
            report_data.append({"module": "Meta Tag Audit", "status": "Failed 🚩", "analysis": "Meta tags are over-stuffed with spammy keywords."})
        else:
            report_data.append({"module": "Meta Tag Audit", "status": "Passed ✅", "analysis": "Meta keywords are clean."})

        links = soup.find_all('a', href=True)
        spam_links = [l for l in links if any(word in l.get('href', '').lower() for word in ['spam', 'casino', 'free'])]
        if len(spam_links) >= 2 or soup.find(class_='footer-spam-links'):
            score += 15
            report_data.append({"module": "Link Farm Detection", "status": "Failed 🚩", "analysis": "Spam Link Farm or irrelevant outbound links detected."})
        else:
            report_data.append({"module": "Link Farm Detection", "status": "Passed ✅", "analysis": "No suspicious link farms found."})

        iframes = soup.find_all('iframe')
        hidden_iframes = [i for i in iframes if 'display:none' in str(i.get('style', '')).replace(' ', '').lower() or 'visibility:hidden' in str(i.get('style', '')).replace(' ', '').lower()]
        if hidden_iframes:
            score += 25
            report_data.append({"module": "Hidden iFrames", "status": "Failed 🚩", "analysis": "Malicious hidden iframes used for traffic hijacking detected."})
        else:
            report_data.append({"module": "Hidden iFrames", "status": "Passed ✅", "analysis": "No deceptive hidden iframes found."})

        refresh_meta = soup.find('meta', attrs={'http-equiv': lambda x: x and x.lower() == 'refresh'})
        if refresh_meta and url not in str(refresh_meta.get('content', '')):
            score += 25
            report_data.append({"module": "Malicious Redirects", "status": "Failed 🚩", "analysis": "Sneaky meta-refresh auto-redirect detected."})
        else:
            report_data.append({"module": "Malicious Redirects", "status": "Passed ✅", "analysis": "No deceptive auto-redirects found."})

        try:
            domain = urlparse(url).netloc.replace("www.", "")
            w = whois.whois(domain)
            creation_date = w.creation_date
            if type(creation_date) is list: creation_date = creation_date[0]

            if creation_date:
                age_days = (datetime.now() - creation_date).days
                if age_days < 30:
                    score += 40
                    report_data.append({"module": "WHOIS Forensics", "status": "Failed 🚩", "analysis": f"Critical: Domain is very new ({age_days} days old). High phishing risk."})
                else:
                    report_data.append({"module": "WHOIS Forensics", "status": "Passed ✅", "analysis": f"Domain age verified ({age_days} days old). Trusted registration."})
            else:
                report_data.append({"module": "WHOIS Forensics", "status": "Suspicious ⚠️", "analysis": "Hidden WHOIS records."})
        except:
            report_data.append({"module": "WHOIS Forensics", "status": "Suspicious ⚠️", "analysis": "WHOIS lookup failed."})

        if AI_ENABLED:
            text_features = vectorizer.transform([text_content])
            if ai_model.predict(text_features)[0] == 1:
                score += 35
                report_data.append({"module": "Machine Learning", "status": "Failed 🚩", "analysis": "Random Forest AI classified this text as Spam."})
            else:
                report_data.append({"module": "Machine Learning", "status": "Passed ✅", "analysis": "AI verified text patterns as safe."})

        if score >= 60: final_status = "Critical Black Hat SEO Detected 🚩"
        elif score > 0: final_status = "Suspicious Activity ⚠️"
        else: final_status = "Safe Website ✅"

        genai_summary = generate_ai_summary(text_content, final_status)

        return final_status, report_data, category, scam_advice, genai_summary

    except Exception as e:
        return f"Error: Scanning Failed", [], "Unknown", "Check URL.", "Could not generate AI summary due to connection error."

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST', 'GET'])
def predict():
    if request.method == 'POST':
        url = request.form.get('url')
        status, report, category, advice, genai_summary = scan_url(url)
        return render_template('index.html', prediction_text=status, report_data=report, url=url, category=category, scam_advice=advice, genai_summary=genai_summary)
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json()
    if not data or 'url' not in data: return jsonify({"error": "No URL provided"}), 400
    
    status, report, category, advice, genai_summary = scan_url(data['url'])
    return jsonify({ "status": status, "category": category, "advice": advice, "genai_summary": genai_summary, "report": report })

if __name__ == '__main__':
    app.run(debug=True, port=5000)