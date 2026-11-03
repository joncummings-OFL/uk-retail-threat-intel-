import os
import sys
import re
import json
import time
import logging
from datetime import datetime, timezone, timedelta
import feedparser
import requests
from bs4 import BeautifulSoup
from google import genai

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# ==============================================================================
# 1. CURATED RSS SOURCES (UK & Global Cybersecurity Intelligence Feeds)
# ==============================================================================
FEEDS = [
    {"name": "NCSC UK Advisories", "url": "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml", "subsector": "supply"},
    {"name": "The Register Security (UK)", "url": "https://www.theregister.com/security/headlines.atom", "subsector": "ecom"},
    {"name": "Computer Weekly Security (UK)", "url": "https://www.computerweekly.com/rss/IT-security.xml", "subsector": "loyalty"},
    {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/", "subsector": "pos"},
    {"name": "The Hacker News", "url": "https://thehackernews.com/feeds/posts/default", "subsector": "ecom"},
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "subsector": "ecom"},
    {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml", "subsector": "pos"},
    {"name": "SecurityWeek", "url": "https://feeds.feedburner.com/securityweek", "subsector": "loyalty"},
    {"name": "Security Affairs", "url": "https://securityaffairs.com/wordpress/feed", "subsector": "supply"},
]

# CISA Known Exploited Vulnerabilities (KEV) Catalog Endpoint (Direct JSON)
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

MAX_ARTICLE_AGE_DAYS = 5

# ==============================================================================
# 2. UK RETAIL TAXONOMY & CRITICAL ENTERPRISE KEYWORDS
# ==============================================================================
RETAIL_KEYWORDS = [
    r"\bretail\b", r"\bretailer\b", r"\bretailers\b", r"\be-commerce\b", r"\becommerce\b",
    r"\bpoint of sale\b", r"\bpos\b", r"\bped\b", r"\bpin pad\b", r"\bcheckout\b",
    r"\bpci[- ]dss\b", r"\b3[- ]?d secure\b", r"\bcardholder\b", r"\bpayment gateway\b",
    r"\bmagecart\b", r"\be-skimming\b", r"\bdigital skimm(er|ing)\b", r"\bweb skimm(er|ing)\b",
    r"\bformjacking\b", r"\btag manager\b", r"\bcheckout injection\b",
    r"\bmagento\b", r"\badobe commerce\b", r"\bwoocommerce\b", r"\bshopify\b",
    r"\bbigcommerce\b", r"\bprestashop\b", r"\bopencart\b", r"\bsalesforce commerce\b",
    r"\bcredential stuffing\b", r"\baccount takeover\b", r"\bato\b", r"\bgift card\b",
    r"\bloyalty\b", r"\bvoucher(s)?\b", r"\breward points\b", r"\bclubcard\b", r"\bnectar\b",
    r"\bsupply chain\b", r"\bwarehouse\b", r"\blogistics\b", r"\bcold-chain\b",
    r"\bdistribution centr(e|es)\b", r"\bcourier(s)?\b", r"\bparcel(s)?\b",
    r"\broyal mail\b", r"\bdpd\b", r"\bevri\b", r"\byodel\b",
    r"\btesco\b", r"\bsainsbury\b", r"\basda\b", r"\bmorrisons\b",
    r"\bmarks & spencer\b", r"\bm&s\b", r"\bboots\b", r"\bcurrys\b", r"\bnext\b",
    r"\bjohn lewis\b", r"\bwaitrose\b", r"\bharrods\b", r"\bocado\b", r"\bargos\b",
    r"\bgreggs\b", r"\bjd sports\b", r"\bprimark\b", r"\bco-op\b",
    r"\bico\b", r"\binformation commissioner\b", r"\buk gdpr\b", r"\baction fraud\b"
]
KEYWORD_PATTERN = re.compile("|".join(RETAIL_KEYWORDS), re.IGNORECASE)

CRITICAL_ENTERPRISE_KEYWORDS = [
    r"\bzero[- ]day\b", r"\b0[- ]day\b", r"\bactively exploited\b", r"\bexploited in the wild\b",
    r"\bknown exploited vulnerability\b", r"\bcisa kev\b", r"\bemergency directive\b",
    r"\bremote code execution\b", r"\bunauthenticated rce\b", r"\bcvss (?:9\.\d|10(?:\.0)?)\b",
    r"\bransomware outbreak\b", r"\bextortion campaign\b", r"\bnation[- ]state\b",
    r"\bpalo alto\b", r"\bfortinet\b", r"\bivanti\b", r"\bcitrix\b", r"\bvmware\b",
    r"\bactive directory\b", r"\bexchange server\b", r"\bwindows kernel\b"
]
CRITICAL_ENTERPRISE_PATTERN = re.compile("|".join(CRITICAL_ENTERPRISE_KEYWORDS), re.IGNORECASE)

CANDIDATE_MODELS = [
    "gemini-3.8-flash",
    "gemini-3.5-flash",
    "gemini-3.5-flash-lite",
]

SCRAPE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
}

def load_previously_seen_urls():
    """Reads existing data/threats.json to prevent repeating alerts."""
    try:
        if os.path.exists("data/threats.json"):
            with open("data/threats.json", "r", encoding="utf-8") as f:
                old_data = json.load(f)
                return {item.get("url") for item in old_data if item.get("url")}
    except Exception as e:
        logging.warning(f"Could not load previous threats.json for deduplication: {e}")
    return set()

def extract_entry_datetime(entry):
    time_struct = entry.get("published_parsed") or entry.get("updated_parsed")
    if time_struct:
        try:
            return datetime.fromtimestamp(time.mktime(time_struct), tz=timezone.utc)
        except Exception:
            pass
    return None

def fetch_cisa_kev_alerts(cutoff_date, seen_urls):
    """
    Directly ingests the official CISA Known Exploited Vulnerabilities (KEV) JSON catalog.
    Captures actively exploited CVEs added within the cutoff window.
    """
    kev_articles = []
    logging.info("Ingesting official CISA KEV JSON catalog...")
    try:
        resp = requests.get(CISA_KEV_URL, headers=SCRAPE_HEADERS, timeout=15)
        if resp.status_code != 200:
            logging.warning(f"CISA KEV endpoint returned HTTP {resp.status_code}")
            return kev_articles

        data = resp.json()
        vulnerabilities = data.get("vulnerabilities", [])

        for vuln in vulnerabilities:
            date_added_str = vuln.get("dateAdded")
            if not date_added_str:
                continue

            try:
                date_added = datetime.strptime(date_added_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except Exception:
                continue

            if date_added < cutoff_date:
                continue

            cve_id = vuln.get("cveID", "Unknown CVE")
            vendor = vuln.get("vendorProject", "Unknown Vendor")
            product = vuln.get("product", "Unknown Product")
            vuln_name = vuln.get("vulnerabilityName", "")
            short_desc = vuln.get("shortDescription", "")
            action = vuln.get("requiredAction", "Apply official vendor security updates immediately.")
            due_date = vuln.get("dueDate", "")
            ransomware_flag = vuln.get("knownRansomwareCampaignUse", "").lower() == "known"

            ref_url = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve_id}"
            is_new = ref_url not in seen_urls

            combined = f"{vendor} {product} {vuln_name} {short_desc}".lower()
            retail_matches = KEYWORD_PATTERN.findall(combined)
            subsector = "ecom" if retail_matches else "enterprise"

            tags = ["CISA KEV", "Active Exploit", cve_id]
            if ransomware_flag:
                tags.append("Ransomware Campaign")

            summary_text = (
                f"{vendor} {product} is affected by {cve_id}. {short_desc} "
                f"Required Remediation: {action} (Federal Due Date: {due_date})."
            )

            # Detect emergency conditions for Flash Alerting
            is_flash = ransomware_flag or (subsector == "ecom" and "remote code execution" in short_desc.lower())

            kev_articles.append({
                "id": f"cisa-kev-{cve_id.lower().replace('-', '_')}",
                "title": f"CISA KEV Alert: {cve_id} in {vendor} {product} Under Active Exploitation",
                "source": "CISA KEV Catalog",
                "url": ref_url,
                "date": date_added.strftime("%d %b %Y"),
                "_timestamp": date_added.timestamp(),
                "is_new": is_new,
                "is_flash": is_flash,
                "severity": "CRITICAL",
                "subsector": subsector,
                "tags": tags[:4],
                "mitre": "T1190 (Exploit Public Facing Application)",
                "summary": summary_text[:350].strip() + ("..." if len(summary_text) > 350 else ""),
                "indicators": [cve_id],
                "advisory": f"Mandatory remediation: {action} Check retail perimeter and server inventory for {product}."
            })

    except Exception as e:
        logging.error(f"Error fetching CISA KEV JSON catalog: {e}")

    logging.info(f"Ingested {len(kev_articles)} active vulnerabilities from CISA KEV catalog.")
    return kev_articles

def fetch_and_filter_intel():
    """Scrapes RSS feeds and the direct CISA KEV catalog with freshness enforcement."""
    matched_articles = []
    seen_urls = load_previously_seen_urls()
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=MAX_ARTICLE_AGE_DAYS)

    # 1. Ingest Direct CISA KEV Feed
    kev_alerts = fetch_cisa_kev_alerts(cutoff_date, seen_urls)
    matched_articles.extend(kev_alerts)

    # 2. Ingest Standard Curated RSS Feeds
    for feed in FEEDS:
        logging.info(f"Ingesting feed: {feed['name']}...")
        try:
            resp = requests.get(feed["url"], headers=SCRAPE_HEADERS, timeout=12)
            if resp.status_code != 200:
                continue

            parsed = feedparser.parse(resp.content)
            for entry in parsed.entries[:25]:
                pub_date = extract_entry_datetime(entry)
                if pub_date and pub_date < cutoff_date:
                    continue

                title = entry.get("title", "").strip()
                summary = entry.get("summary", "") or entry.get("description", "")
                link = entry.get("link", "").strip()

                clean_summary = BeautifulSoup(summary, "html.parser").get_text()
                combined_text = f"{title} {clean_summary}"

                retail_matches = KEYWORD_PATTERN.findall(combined_text)
                crit_matches = CRITICAL_ENTERPRISE_PATTERN.findall(combined_text)
                is_global_critical = bool(crit_matches) or ("advisory" in feed["name"].lower() and "critical" in combined_text.lower())

                if retail_matches or is_global_critical:
                    date_display = pub_date.strftime("%d %b %Y") if pub_date else "Recent"
                    is_new_threat = link not in seen_urls

                    if retail_matches:
                        subsector = feed["subsector"]
                        is_crit = is_global_critical or any(k in combined_text.lower() for k in [
                            "ransomware", "magecart", "breach", "zero-day", "cvv", "skimmer"
                        ])
                        severity = "CRITICAL" if is_crit else "HIGH"
                        tags = list(set([m[0].upper() + m[1:].lower() for m in retail_matches if isinstance(m, str)]))[:4]
                        advisory_text = "Review logs and e-commerce infrastructure for exposure to this vector."
                    else:
                        subsector = "enterprise"
                        severity = "CRITICAL"
                        tags = ["Global 0-Day", "Enterprise"] + list(set([m[0].upper() + m[1:].lower() for m in crit_matches if isinstance(m, str)]))[:2]
                        advisory_text = "Urgent: Patch edge devices, audit perimeter gateways, and review EDR/SOC telemetry immediately."

                    # Identify breaking emergency threats for Flash Alerts
                    is_flash_threat = is_new_threat and severity == "CRITICAL" and any(
                        term in combined_text.lower() for term in [
                            "actively exploited in the wild", "0-day", "zero-day", 
                            "emergency directive", "critical checkout breach"
                        ]
                    )

                    matched_articles.append({
                        "id": f"scraped-{len(matched_articles) + 1}",
                        "title": title,
                        "source": feed["name"],
                        "url": link,
                        "date": date_display,
                        "_timestamp": pub_date.timestamp() if pub_date else 0,
                        "is_new": is_new_threat,
                        "is_flash": is_flash_threat,
                        "severity": severity,
                        "subsector": subsector,
                        "tags": tags,
                        "mitre": "T1190 (Exploit Public Facing Application)" if subsector in ["ecom", "enterprise"] else "T1078 (Valid Accounts)",
                        "summary": clean_summary[:350].strip() + ("..." if len(clean_summary) > 350 else ""),
                        "indicators": [link] if link else [],
                        "advisory": advisory_text
                    })
        except Exception as e:
            logging.error(f"Error scraping {feed['name']}: {e}")

    matched_articles.sort(key=lambda x: (x.get("is_new", False), x.get("_timestamp", 0)), reverse=True)
    new_count = sum(1 for a in matched_articles if a.get("is_new"))
    logging.info(f"Retrieved {len(matched_articles)} total alerts ({new_count} brand-new today).")
    return matched_articles

def generate_ciso_daily_brief(articles):
    """Synthesizes concise daily CISO briefing under 100 words."""
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return "GEMINI_API_KEY not set. Daily briefing skipped."

    client = genai.Client(api_key=api_key)
    new_articles = [a for a in articles if a.get("is_new")]
    focus_articles = new_articles[:6] if new_articles else articles[:5]
    has_new_activity = len(new_articles) > 0

    prompt = f"""
    Act as a Principal Cyber Threat Intelligence Analyst for the UK Retail Sector.
    Review the following threat items ({'NEW developments today' if has_new_activity else 'Ongoing active sector threats'}):

    {json.dumps(focus_articles, indent=2)}

    Generate an ultra-brief CISO briefing tailored for mobile/chat reading.
    STRICT CONSTRAINT: Keep your entire response under 100 words. Do NOT repeat yesterday's generic summaries.

    Provide EXACTLY this structure:
    *TL;DR:* 1 or 2 crisp sentences summarizing today's posture ({'highlighting newly observed vectors' if has_new_activity else 'noting no major new overnight breaches, surveillance posture maintained on existing perimeter and loyalty threats'}).
    *Key Alert:* 1 single sentence pinpointing the highest-risk item affecting UK retail or enterprise perimeter.
    *Priority Action:* 1 concise action item for retail SecOps.

    No greeting, no outro, no markdown headers (###), just those 3 bullet points.
    """

    for model_name in CANDIDATE_MODELS:
        for attempt in range(1, 4):
            try:
                response = client.models.generate_content(model=model_name, contents=prompt)
                if response and response.text:
                    return response.text.strip()
            except Exception as e:
                logging.warning(f"Error on {model_name} (attempt {attempt}/3): {e}")
                time.sleep(attempt * 3)

    return (
        "*TL;DR:* Overnight sector surveillance active. Monitored feeds show steady threat activity with no critical retail breaches reported in the last 12 hours.\n"
        "*Priority Action:* Maintain continuous CSP script monitoring and inspect loyalty API authentication rates."
    )

def generate_weekly_executive_rollup(articles):
    """
    Synthesizes a strategic, macro-level Weekly Cyber Threat Intelligence Executive Rollup.
    Designed for Friday leadership briefings, board summaries, and weekend on-call guidance.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return "GEMINI_API_KEY not set. Weekly rollup skipped."

    client = genai.Client(api_key=api_key)
    top_items = articles[:15]

    prompt = f"""
    Act as the Chief Information Security Officer (CISO) and Lead Threat Intel Director for the UK Retail Sector.
    Review all cyber security intelligence gathered across UK retail, high street POS, e-commerce, and supply chains this week:

    {json.dumps(top_items, indent=2)}

    Generate a Strategic Weekly Executive Threat Intelligence Rollup for retail executives and SecOps leadership.
    Structure the response with:
    1. **Executive Macro Summary**: 2-3 sentences analyzing key attack vectors observed across UK retail this week.
    2. **Dominant Attack Trends**: Detail shifts in threat actor tactics (e.g. 3PL logistics extortion, e-commerce checkout tag tampering, loyalty ATO, edge appliance 0-days).
    3. **Regulatory & Audit Posture**: Concrete implications for PCI-DSS v4.0.1 compliance and UK GDPR/ICO 72h disclosure readiness.
    4. **Weekend On-Call & Proactive Guardrails**: 3 prioritized safeguards for security operations and IT store teams heading into the weekend.

    Format cleanly in professional Markdown with bullet points.
    """

    for model_name in CANDIDATE_MODELS:
        for attempt in range(1, 4):
            try:
                response = client.models.generate_content(model=model_name, contents=prompt)
                if response and response.text:
                    return response.text.strip()
            except Exception as e:
                logging.warning(f"Weekly Rollup error on {model_name} (attempt {attempt}/3): {e}")
                time.sleep(attempt * 3)

    return (
        "## UK Retail Weekly Threat Rollup\n\n"
        "Weekly synthesis completed. Threat levels remain ELEVATED across client-side script integrations and perimeter gateways."
    )

def build_google_spaces_payload(briefing, articles, is_weekly=False):
    """Builds a formatted message (< 1,400 chars) for Google Chat / Spaces."""
    today_str = datetime.now(timezone.utc).strftime("%d %b %Y")
    dashboard_url = os.getenv("DASHBOARD_URL", "")

    clean_brief = briefing.replace("**", "*")

    if is_weekly:
        title_banner = f"📊 *UK RETAIL WEEKLY CYBER THREAT ROLLUP* • _{today_str}_\n\n"
    else:
        title_banner = f"🛡️ *UK RETAIL CYBER THREAT BRIEFING* • _{today_str}_\n\n"

    message = (
        title_banner +
        f"{clean_brief}\n\n"
        "───────────────────────────────────\n"
        "*🔥 Top Priority Threats This Cycle:*\n"
    )

    pertinent = articles[:4] if is_weekly else articles[:3]
    if pertinent:
        for idx, art in enumerate(pertinent, start=1):
            severity_icon = "🔴" if art["severity"] == "CRITICAL" else "🟠"
            new_tag = " [NEW]" if art.get("is_new") else ""
            title = art["title"]
            url = art.get("url")
            source = art["source"]

            if len(title) > 72:
                title = title[:69] + "..."

            if url:
                message += f"{idx}. {severity_icon}{new_tag} <{url}|{title}> — _{source}_\n"
            else:
                message += f"{idx}. {severity_icon}{new_tag} *{title}* — _{source}_\n"
    else:
        message += "• _No critical sector alerts detected in the last cycle._\n"

    message += "───────────────────────────────────\n"
    if dashboard_url:
        message += f"👉 *Live Threat Telemetry & IoCs on Hub:*\n<{dashboard_url}|Open UK Retail Threat Hub ↗>"
    else:
        message += "👉 *Visit your interactive Threat Hub for full technical IoCs & advisories.*"

    return message

def build_flash_alert_payload(flash_article):
    """Generates an urgent high-priority Google Chat dispatch for breaking emergency threats."""
    today_str = datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M UTC")
    dashboard_url = os.getenv("DASHBOARD_URL", "")

    title = flash_article.get("title", "High-Priority Cyber Incident")
    url = flash_article.get("url", "")
    advisory = flash_article.get("advisory", "Isolate exposed endpoints and patch immediately.")
    summary = flash_article.get("summary", "")

    msg = (
        "🚨🚨🚨 *UK RETAIL CYBER SECURITY FLASH ALERT* 🚨🚨🚨\n"
        f"⏱️ _Dispatched: {today_str}_\n\n"
        f"*INCIDENT:* *{title}*\n"
        f"*SOURCE:* _{flash_article.get('source', 'Threat Intel Feed')}_\n\n"
        f"*EXECUTIVE SYNOPSIS:*\n{summary}\n\n"
        f"⚡ *MANDATORY ACTION:* {advisory}\n"
    )

    if url:
        msg += f"\n🔗 *Source Report:* <{url}|Open Original Advisory ↗>"
    if dashboard_url:
        msg += f"\n🌐 *Live Incident Hub:* <{dashboard_url}|Open Threat Hub ↗>"

    return msg

def save_output_files(articles, briefing, is_weekly=False):
    """Saves structured data, flash alert states, and markdown briefings into the /data folder."""
    os.makedirs("data", exist_ok=True)

    with open("data/threats.json", "w", encoding="utf-8") as f:
        json.dump(articles, f, indent=2, ensure_ascii=False)

    # Check for active flash alerts
    flash_items = [a for a in articles if a.get("is_flash")]
    if flash_items:
        with open("data/flash_alert.json", "w", encoding="utf-8") as f:
            json.dump(flash_items[0], f, indent=2, ensure_ascii=False)
    elif os.path.exists("data/flash_alert.json"):
        try:
            os.remove("data/flash_alert.json")
        except OSError:
            pass

    summary_filename = "data/weekly_summary.md" if is_weekly else "data/daily_summary.md"
    with open(summary_filename, "w", encoding="utf-8") as f:
        f.write(briefing)

    logging.info(f"Saved data/threats.json and {summary_filename} successfully.")

def notify_webhook(message_text):
    webhook_url = (
        os.getenv("WEBHOOK_URL") 
        or os.getenv("GOOGLE_CHAT_WEBHOOK_URL") 
        or os.getenv("SLACK_WEBHOOK_URL")
    )
    if not webhook_url:
        logging.info("No webhook URL configured. Skipping notifications.")
        return

    payload = {"text": message_text}
    try:
        res = requests.post(
            webhook_url, 
            headers={"Content-Type": "application/json; charset=UTF-8"},
            json=payload, 
            timeout=10
        )
        if res.status_code in [200, 204]:
            logging.info("Dispatched briefing to Google Space successfully.")
        else:
            logging.error(f"Webhook rejected with HTTP {res.status_code}: {res.text}")
    except Exception as e:
        logging.error(f"Failed to post to webhook: {e}")

if __name__ == "__main__":
    is_weekly_run = ("--weekly" in sys.argv) or (os.getenv("RUN_MODE", "").lower() == "weekly")
    is_flash_mode = ("--flash" in sys.argv) or (os.getenv("RUN_MODE", "").lower() == "flash")

    logging.info(f"Executing UK Retail Threat Intelligence Run (Mode: {'FLASH ALERT' if is_flash_mode else ('WEEKLY ROLLUP' if is_weekly_run else 'DAILY BRIEFING')})...")

    items = fetch_and_filter_intel()

    # Flash alert priority handling
    flash_candidates = [a for a in items if a.get("is_flash")]
    if is_flash_mode or flash_candidates:
        top_flash = flash_candidates[0] if flash_candidates else items[0]
        logging.info(f"🚨 Flash Alert triggered: {top_flash.get('title')}")
        flash_msg = build_flash_alert_payload(top_flash)
        notify_webhook(flash_msg)

    if is_weekly_run:
        summary_text = generate_weekly_executive_rollup(items)
    else:
        summary_text = generate_ciso_daily_brief(items)

    save_output_files(items, summary_text, is_weekly=is_weekly_run)

    if not is_flash_mode:
        formatted_msg = build_google_spaces_payload(summary_text, items, is_weekly=is_weekly_run)
        notify_webhook(formatted_msg)

    logging.info("Run complete.")
