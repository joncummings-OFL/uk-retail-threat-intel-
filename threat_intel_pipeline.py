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
                title = entry.get("title", "").strip()
                summary = entry.get("summary", "") or entry.get("description", "")
                link = entry.get("link", "").strip()
                
                clean_summary = BeautifulSoup(summary, "html.parser").get_text()
                combined_text = f"{title} {clean_summary}"
                
                matches = KEYWORD_PATTERN.findall(combined_text)
                if matches:
                    matched_articles.append({
                        "id": f"scraped-{len(matched_articles) + 1}",
                        "title": title,
                        "source": feed["name"],
                        "url": link,
                        "date": datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M UTC"),
                        "severity": "CRITICAL" if any(k in combined_text.lower() for k in ["ransomware", "magecart", "breach", "zero-day", "cvv"]) else "HIGH",
                        "subsector": feed["subsector"],
                        "tags": list(set([m.lower().capitalize() for m in matches]))[:4],
                        "mitre": "T1190 (Exploit Public Facing Application)" if "ecom" in feed["subsector"] else "T1078 (Valid Accounts)",
                        "summary": clean_summary[:350].strip() + ("..." if len(clean_summary) > 350 else ""),
                        "indicators": [link] if link else [],
                        "advisory": "Review logs and e-commerce infrastructure for exposure to this vector."
                    })
        except Exception as e:
            logging.error(f"Error scraping {feed['name']}: {e}")

    logging.info(f"Retrieved {len(matched_articles)} retail-relevant alerts.")
    return matched_articles

def generate_ciso_daily_brief(articles):
    """
    Synthesizes an executive CISO threat briefing via Gemini API
    with automatic exponential backoff on 503 high-demand errors.
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
    1. **Executive TL;DR**: 2-3 crisp sentences summarizing UK retail cyber exposure today.
    2. **Critical Incidents & Exploits**: Highlight top vulnerabilities (e.g. Magecart, POS, Supply Chain, ATO).
    3. **UK Regulatory & Compliance Impact**: UK GDPR / ICO 72h notifications and PCI-DSS v4.0.1 implications.
    4. **Tactical MITRE ATT&CK Mapping**: Key tactics observed.
    5. **Immediate Defensive Recommendations for Retail CISOs**: 3 actionable, prioritized controls.

    Format cleanly in Markdown with bullet points. Avoid unnecessary introductory text.
    """

    last_error = None
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
                time.sleep(attempt * 3)

    logging.error(f"All candidate models saturated. Final error: {last_error}")
    return (
        "*Executive TL;DR*\n"
        "AI executive synthesis temporarily unavailable due to upstream capacity. "
        f"Filtered {len(articles)} high-priority retail advisories below for immediate analyst review."
    )

def format_for_google_chat(markdown_text):
    """
    Converts generic markdown into clean Google Chat format:
    - Headers (###) converted to bold section labels
    - Standard markdown links [Title](URL) converted to Google Chat <URL|Title>
    - Standard double asterisks **bold** normalized to *bold*
    - Dashes converted to clean bullet points
    """
    text = markdown_text

    # Convert [Title](URL) -> <URL|Title>
    text = re.sub(r'\[([^\]]+)\]\((https?://[^\)]+)\)', r'<\2|\1>', text)

    # Convert headers (### Heading) -> *◈ HEADING*
    text = re.sub(r'#{1,4}\s*(.*)', r'\n*◈ \1*', text)

    # Normalize **bold** to *bold* for Google Chat
    text = re.sub(r'\*\*(.*?)\*\*', r'*\1*', text)

    # Replace leading list hyphens with clean unicode bullets
    text = re.sub(r'^\s*[\-\*]\s+', r'  • ', text, flags=re.MULTILINE)

    return text.strip()

def build_google_spaces_payload(briefing, articles):
    """
    Wraps the AI briefing with an executive header, a link to the live dashboard,
    and direct source citations for all ingested threat reports.
    """
    today_str = datetime.now(timezone.utc).strftime("%d %b %Y")
    dashboard_url = os.getenv("DASHBOARD_URL", "")

    # Top banner & dashboard link
    header = (
        "╔══════════════════════════════════════════════╗\n"
        "🛡️ *UK RETAIL CYBER THREAT INTELLIGENCE*\n"
        f"📅 _Daily CISO Executive Briefing — {today_str}_\n"
        "╚══════════════════════════════════════════════╝\n\n"
    )

    if dashboard_url:
        header += f"🌐 *Interactive SOC Dashboard:* <{dashboard_url}|Open Live Threat Hub>\n"
    else:
        header += "🌐 *Live Dashboard:* _(Set DASHBOARD_URL in GitHub repo variables for 1-click link)_\n"

    header += "───────────────────────────────────────────────\n\n"

    # Format the AI content
    styled_briefing = format_for_google_chat(briefing)

    # Build the clickable sources section
    sources_section = "\n\n───────────────────────────────────────────────\n"
    sources_section += "*📑 Monitored Sources & Verified Incident Links:*\n"

    if articles:
        for idx, art in enumerate(articles[:6], start=1):
            severity_icon = "🔴" if art["severity"] == "CRITICAL" else "🟠"
            title = art["title"]
            source = art["source"]
            url = art.get("url")

            if url:
                sources_section += f"{idx}. {severity_icon} <{url}|{title}> — _{source}_\n"
            else:
                sources_section += f"{idx}. {severity_icon} *{title}* — _{source}_\n"
    else:
        sources_section += "_No direct critical vector alerts matched today's filter taxonomy._\n"

    return header + styled_briefing + sources_section

def save_output_files(articles, briefing):
    """Saves structured data into the /data folder for dashboard ingestion."""
    os.makedirs("data", exist_ok=True)
    
    with open("data/threats.json", "w", encoding="utf-8") as f:
        json.dump(articles, f, indent=2, ensure_ascii=False)
        
    with open("data/daily_summary.md", "w", encoding="utf-8") as f:
        f.write(briefing)

    logging.info("Saved data/threats.json and data/daily_summary.md successfully.")

def notify_webhook(message_text):
    """
    Dispatches message to Google Spaces.
    Chunks text at 3,800 characters to stay within Google Chat's 4,096-character limit.
    """
    webhook_url = (
        os.getenv("WEBHOOK_URL") 
        or os.getenv("GOOGLE_CHAT_WEBHOOK_URL") 
        or os.getenv("SLACK_WEBHOOK_URL")
    )
    if not webhook_url:
        logging.info("No webhook URL configured. Skipping notifications.")
        return

    MAX_CHUNK = 3800
    chunks = [message_text[i:i + MAX_CHUNK] for i in range(0, len(message_text), MAX_CHUNK)]

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
                logging.info(f"Dispatched briefing chunk {idx+1}/{len(chunks)} to Google Space.")
            else:
                logging.error(f"Webhook rejected with HTTP {res.status_code}: {res.text}")
        except Exception as e:
            logging.error(f"Failed to post to webhook: {e}")

if __name__ == "__main__":
    logging.info("Executing UK Retail Threat Intelligence Run...")
    items = fetch_and_filter_intel()
    brief = generate_ciso_daily_brief(items)
    save_output_files(items, brief)
    
    # Build the styled Google Spaces briefing with live links
    formatted_message = build_google_spaces_payload(brief, items)
    notify_webhook(formatted_message)
    logging.info("Run complete.")
