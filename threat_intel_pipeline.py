import os
import re
import json
import time
import logging
from datetime import datetime, timezone
import feedparser
import requests
from bs4 import BeautifulSoup
from google import genai

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# 1. CURATED SOURCES (UK & Global Cybersecurity Feeds)
FEEDS = [
    {"name": "NCSC UK Advisories", "url": "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml", "subsector": "supply"},
    {"name": "The Register Security (UK)", "url": "https://www.theregister.com/security/headlines.atom", "subsector": "ecom"},
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "subsector": "ecom"},
    {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml", "subsector": "pos"},
    {"name": "SecurityWeek", "url": "https://feeds.feedburner.com/securityweek", "subsector": "loyalty"},
]

# 2. UK RETAIL KEYWORD TAXONOMY
RETAIL_KEYWORDS = [
    r"\bretail\b", r"\be-commerce\b", r"\becommerce\b", r"\bpoint of sale\b", r"\bpos\b",
    r"\bmagecart\b", r"\be-skimming\b", r"\bcheckout\b", r"\bpci[- ]dss\b", r"\bloyalty\b",
    r"\bcredential stuffing\b", r"\baccount takeover\b", r"\bato\b", r"\bgift card\b",
    r"\bsupply chain\b", r"\bwarehouse\b", r"\blogistics\b", r"\bico\b", r"\bshop\b",
    r"\btesco\b", r"\bsainsbury\b", r"\basda\b", r"\bmarks & spencer\b", r"\bm&s\b",
    r"\bboots\b", r"\bcurrys\b", r"\bnext\b", r"\bjohn lewis\b", r"\bharrods\b"
]
KEYWORD_PATTERN = re.compile("|".join(RETAIL_KEYWORDS), re.IGNORECASE)

# Models to attempt in order of preference if 503 high-demand errors occur
CANDIDATE_MODELS = [
    "gemini-3.8-flash",
    "gemini-3.5-flash",
    "gemini-3.5-flash-lite",
]

def fetch_and_filter_intel():
    """Scrapes RSS feeds and matches articles against the UK retail taxonomy."""
    matched_articles = []
    
    for feed in FEEDS:
        logging.info(f"Ingesting feed: {feed['name']}...")
        try:
            parsed = feedparser.parse(feed["url"])
            for entry in parsed.entries[:20]:
                title = entry.get("title", "")
                summary = entry.get("summary", "") or entry.get("description", "")
                link = entry.get("link", "")
                
                clean_summary = BeautifulSoup(summary, "html.parser").get_text()
                combined_text = f"{title} {clean_summary}"
                
                matches = KEYWORD_PATTERN.findall(combined_text)
                if matches:
                    matched_articles.append({
                        "id": f"scraped-{len(matched_articles) + 1}",
                        "title": title.strip(),
                        "source": feed["name"],
                        "date": datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M UTC"),
                        "severity": "CRITICAL" if any(k in combined_text.lower() for k in ["ransomware", "magecart", "breach", "zero-day", "cvv"]) else "HIGH",
                        "subsector": feed["subsector"],
                        "tags": list(set([m.lower().capitalize() for m in matches]))[:4],
                        "mitre": "T1190 (Exploit Public Facing Application)" if "ecom" in feed["subsector"] else "T1078 (Valid Accounts)",
                        "summary": clean_summary[:350].strip() + ("..." if len(clean_summary) > 350 else ""),
                        "indicators": [link],
                        "advisory": "Review logs and e-commerce infrastructure for exposure to this vector."
                    })
        except Exception as e:
            logging.error(f"Error scraping {feed['name']}: {e}")

    logging.info(f"Retrieved {len(matched_articles)} retail-relevant alerts.")
    return matched_articles

def generate_ciso_daily_brief(articles):
    """
    Uses Gemini API to synthesize an executive CISO threat briefing.
    Includes automated retries and fallback models to gracefully handle 503 errors.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        logging.warning("GEMINI_API_KEY is not set. Generating fallback summary.")
        return "GEMINI_API_KEY was not provided. Daily briefing could not be generated."

    client = genai.Client(api_key=api_key)

    prompt = f"""
    Act as a Principal Cyber Threat Intelligence Analyst for the UK Retail Sector.
    Review the following raw scraped cyber security news and indicators collected today:

    {json.dumps(articles[:10], indent=2)}

    Generate a high-impact Daily Cyber Threat Intelligence Executive Briefing containing:
    1. **Executive TL;DR**: 2-3 sentences on the prevailing UK retail threat landscape today.
    2. **Critical Incidents & Exploits**: Highlight top vulnerabilities (e.g. Magecart, POS, Supply Chain, ATO).
    3. **UK Regulatory & Compliance Impact**: Potential UK GDPR / ICO / PCI-DSS v4.0.1 implications.
    4. **Tactical MITRE ATT&CK Mapping**: Key tactics observed.
    5. **Immediate Defensive Recommendations for Retail CISOs**: Actionable steps for SecOps.

    Format cleanly in professional Markdown with bullet points. Avoid excessive fluff.
    """

    last_error = None

    # Cascade through candidate models with exponential backoff on 503/transient errors
    for model_name in CANDIDATE_MODELS:
        for attempt in range(1, 4):
            try:
                logging.info(f"Requesting briefing from {model_name} (attempt {attempt}/3)...")
                response = client.models.generate_content(
                    model=model_name,
                    contents=prompt
                )
                if response and response.text:
                    logging.info(f"Successfully generated briefing using {model_name}.")
                    return response.text
            except Exception as e:
                last_error = e
                logging.warning(f"Error on {model_name} (attempt {attempt}/3): {e}")
                time.sleep(attempt * 3)  # Wait 3s, then 6s before retry

    # Clean fallback output if all model endpoints are temporarily saturated
    logging.error(f"All candidate models saturated. Final error: {last_error}")
    return (
        "⚠️ *UK Retail Threat Briefing — Fallback Mode*\n\n"
        f"AI executive briefing generation was temporarily delayed by upstream API demand.\n\n"
        f"**Latest Filtered Threats Today ({len(articles)} alerts captured):**\n" +
        "\n".join([f"• *[{a['severity']}]* {a['title']} — _{a['source']}_" for a in articles[:7]])
    )

def save_output_files(articles, briefing):
    """Saves structured data into the /data folder for dashboard ingestion."""
    os.makedirs("data", exist_ok=True)
    
    with open("data/threats.json", "w", encoding="utf-8") as f:
        json.dump(articles, f, indent=2, ensure_ascii=False)
        
    with open("data/daily_summary.md", "w", encoding="utf-8") as f:
        f.write(briefing)

    logging.info("Saved data/threats.json and data/daily_summary.md successfully.")

def notify_webhook(briefing):
    """
    Sends summary to Google Spaces/Chat, Slack, or Teams.
    Supports either WEBHOOK_URL, GOOGLE_CHAT_WEBHOOK_URL, or SLACK_WEBHOOK_URL.
    """
    webhook_url = (
        os.getenv("WEBHOOK_URL") 
        or os.getenv("GOOGLE_CHAT_WEBHOOK_URL") 
        or os.getenv("SLACK_WEBHOOK_URL")
    )
    if not webhook_url:
        logging.info("No webhook URL configured. Skipping notifications.")
        return

    full_message = f"🛡️ *UK Retail Daily Cyber Threat Briefing*\n\n{briefing}"

    # Google Chat / Spaces has a strict 4096 character limit per message.
    # Chunk long briefings so Google does not reject with 400 Bad Request.
    MAX_CHUNK = 3800
    chunks = [full_message[i:i + MAX_CHUNK] for i in range(0, len(full_message), MAX_CHUNK)]

    for idx, chunk in enumerate(chunks):
        payload = {"text": chunk}
        try:
            res = requests.post(
                webhook_url, 
                headers={"Content-Type": "application/json; charset=UTF-8"},
                json=payload, 
                timeout=10
            )
            if res.status_code in [200, 204]:
                logging.info(f"Dispatched briefing chunk {idx+1}/{len(chunks)} to webhook.")
            else:
                logging.error(f"Webhook rejected with HTTP {res.status_code}: {res.text}")
        except Exception as e:
            logging.error(f"Failed to post to webhook: {e}")

if __name__ == "__main__":
    logging.info("Executing UK Retail Threat Intelligence Run...")
    items = fetch_and_filter_intel()
    brief = generate_ciso_daily_brief(items)
    save_output_files(items, brief)
    notify_webhook(brief)
    logging.info("Run complete.")
