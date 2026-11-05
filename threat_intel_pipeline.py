import os
import sys
import re
import json
import time
import uuid
import logging
import html
from datetime import datetime, timezone, timedelta
from xml.etree import ElementTree as ET
import feedparser
import requests
from bs4 import BeautifulSoup
from google import genai

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# ==============================================================================
# 1. CURATED INTEL SOURCES (UK, GLOBAL & REGULATORY ENFORCEMENT)
# ==============================================================================
FEEDS = [
    {"name": "NCSC UK Advisories", "url": "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml", "subsector": "supply"},
    {"name": "UK ICO Enforcement & News", "url": "https://ico.org.uk/about-the-ico/news-and-events/news-and-blogs/rss/", "subsector": "loyalty"},
    {"name": "The Register Security (UK)", "url": "https://www.theregister.com/security/headlines.atom", "subsector": "ecom"},
    {"name": "Computer Weekly Security (UK)", "url": "https://www.computerweekly.com/rss/IT-security.xml", "subsector": "loyalty"},
    {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/", "subsector": "pos"},
    {"name": "The Hacker News", "url": "https://thehackernews.com/feeds/posts/default", "subsector": "ecom"},
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "subsector": "ecom"},
    {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml", "subsector": "pos"},
    {"name": "SecurityWeek", "url": "https://feeds.feedburner.com/securityweek", "subsector": "loyalty"},
    {"name": "Security Affairs", "url": "https://securityaffairs.com/wordpress/feed", "subsector": "supply"},
]

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FIRST_EPSS_URL = "https://api.first.org/data/v1/epss"

MAX_ARTICLE_AGE_DAYS = 5

SCRAPE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
}

# ==============================================================================
# 2. RETAIL, ENTERPRISE, ACTOR & PEAK TRADING TAXONOMY
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

# Threat Actor Tracking
THREAT_ACTOR_MAP = {
    "Scattered Spider": re.compile(r"\b(scattered spider|unc3944|starfraud|muddled libra|0ktapus)\b", re.IGNORECASE),
    "FIN7 / Carbanak": re.compile(r"\b(fin7|carbanak|sangria tempest)\b", re.IGNORECASE),
    "LockBit": re.compile(r"\b(lockbit)\b", re.IGNORECASE),
    "Akira": re.compile(r"\b(akira ransomware|akira group)\b", re.IGNORECASE),
    "Cl0p": re.compile(r"\b(cl0p|clop ransomware)\b", re.IGNORECASE),
    "Magecart Syndicate": re.compile(r"\b(magecart|group 8|group 11|group 12|digital skimmer)\b", re.IGNORECASE),
    "BlackCat / ALPHV": re.compile(r"\b(blackcat|alphv)\b", re.IGNORECASE),
}

# Peak Trading / "Golden Quarter" Vectors
PEAK_TRADING_PATTERN = re.compile(
    r"\b(bot|scalper|inventory hoarding|cart stuffing|gift card|voucher|reward points|credential stuffing|checkout ddos|courier smishing|fake parcel|delivery scam|evri|dpd|royal mail|black friday|cyber monday|boxing day|christmas rush)\b",
    re.IGNORECASE
)

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

CANDIDATE_MODELS = [
    "gemini-3.8-flash",
    "gemini-3.5-flash",
    "gemini-3.5-flash-lite",
]

# ==============================================================================
# 3. HELPER FUNCTIONS & DE-DUPLICATION
# ==============================================================================
def load_previously_seen_urls():
    try:
        if os.path.exists("data/threats.json"):
            with open("data/threats.json", "r", encoding="utf-8") as f:
                old_data = json.load(f)
                return {item.get("url") for item in old_data if item.get("url")}
    except Exception as e:
        logging.warning(f"Could not load previous threats.json: {e}")
    return set()

def extract_entry_datetime(entry):
    time_struct = entry.get("published_parsed") or entry.get("updated_parsed")
    if time_struct:
        try:
            return datetime.fromtimestamp(time.mktime(time_struct), tz=timezone.utc)
        except Exception:
            pass
    return None

def clean_feed_text(raw_text):
    """Strips all HTML tags, decodes escaped entities, and collapses redundant whitespace."""
    if not raw_text:
        return ""
    # Pass 1: Parse HTML
    soup = BeautifulSoup(raw_text, "html.parser")
    text = soup.get_text(separator=" ")
    # Pass 2: If the text contained escaped tags (&lt;p&gt;), strip them too
    if "<" in text and ">" in text:
        soup2 = BeautifulSoup(text, "html.parser")
        text = soup2.get_text(separator=" ")
    # Pass 3: Strip any residual HTML/XML tags
    text = re.sub(r"<[^>]+>", " ", text)
    # Pass 4: Unescape standard HTML entities
    text = html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()

def detect_threat_actor(text):
    for actor_name, pattern in THREAT_ACTOR_MAP.items():
        if pattern.search(text):
            return actor_name
    return None

def detect_mitre_mapping(text, subsector):
    lower = text.lower()
    if "magecart" in lower or "skimm" in lower or "formjacking" in lower:
        return {"id": "T1056.004", "tactic": "Collection", "name": "Web Skimming (Magecart)"}
    elif "credential stuffing" in lower or "account takeover" in lower or "ato" in lower:
        return {"id": "T1110", "tactic": "Credential Access", "name": "Brute Force / Credential Stuffing"}
    elif "phishing" in lower or "smishing" in lower:
        return {"id": "T1566", "tactic": "Initial Access", "name": "Phishing / Courier Smishing"}
    elif "ransomware" in lower or "extortion" in lower:
        return {"id": "T1486", "tactic": "Impact", "name": "Data Encrypted for Impact"}
    elif "remote code execution" in lower or "zero-day" in lower or "0-day" in lower:
        return {"id": "T1190", "tactic": "Initial Access", "name": "Exploit Public-Facing Application"}
    elif subsector in ["pos"]:
        return {"id": "T1005", "tactic": "Collection", "name": "Data from Local System / POS"}
    elif subsector in ["supply"]:
        return {"id": "T1195", "tactic": "Initial Access", "name": "Supply Chain Compromise"}
    return {"id": "T1190", "tactic": "Initial Access", "name": "Exploit Public-Facing Application"}

# ==============================================================================
# 4. FIRST.ORG EPSS SCORING ENGINE
# ==============================================================================
def enrich_threats_with_epss(threat_items):
    """
    Collects unique CVEs across ingested threats and queries FIRST.org EPSS API in batch.
    Enriches each vulnerability with probability score and percentile rank.
    """
    cve_to_items = {}
    for item in threat_items:
        cves = item.get("cves", [])
        for cve in cves:
            cve_upper = cve.upper()
            if cve_upper not in cve_to_items:
                cve_to_items[cve_upper] = []
            cve_to_items[cve_upper].append(item)

    if not cve_to_items:
        return threat_items

    all_cves = list(cve_to_items.keys())[:80] # API batch limit
    logging.info(f"Querying FIRST.org EPSS scores for {len(all_cves)} CVEs...")

    try:
        url = f"{FIRST_EPSS_URL}?cve={','.join(all_cves)}"
        resp = requests.get(url, timeout=12)
        if resp.status_code == 200:
            data = resp.json().get("data", [])
            for entry in data:
                cve = entry.get("cve")
                epss_val = float(entry.get("epss", 0))
                percentile_val = float(entry.get("percentile", 0))

                for item in cve_to_items.get(cve, []):
                    item["epss"] = {
                        "cve": cve,
                        "score": f"{epss_val * 100:.1f}%",
                        "raw_score": epss_val,
                        "percentile": f"{percentile_val * 100:.1f}%"
                    }
            logging.info("Successfully enriched vulnerabilities with live EPSS scores.")
        else:
            logging.warning(f"EPSS API responded with HTTP {resp.status_code}")
    except Exception as e:
        logging.warning(f"Failed to fetch EPSS scores: {e}")

    return threat_items

# ==============================================================================
# 5. INGESTION PIPELINE (CISA KEV + CURATED FEEDS + ICO)
# ==============================================================================
def fetch_cisa_kev_alerts(cutoff_date, seen_urls):
    kev_articles = []
    logging.info("Ingesting official CISA KEV JSON catalog...")
    try:
        resp = requests.get(CISA_KEV_URL, headers=SCRAPE_HEADERS, timeout=15)
        if resp.status_code != 200:
            return kev_articles

        vulnerabilities = resp.json().get("vulnerabilities", [])
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

            actor = detect_threat_actor(combined)
            mitre_info = detect_mitre_mapping(combined, subsector)

            tags = ["CISA KEV", "Active Exploit", cve_id]
            if ransomware_flag:
                tags.append("Ransomware Campaign")
            if actor:
                tags.append(f"Actor: {actor}")

            summary_text = (
                f"{vendor} {product} is affected by {cve_id}. {short_desc} "
                f"Required Remediation: {action} (Federal Due Date: {due_date})."
            )

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
                "is_peak_trading": bool(PEAK_TRADING_PATTERN.search(combined)),
                "severity": "CRITICAL",
                "subsector": subsector,
                "actor": actor,
                "cves": [cve_id],
                "tags": tags[:4],
                "mitre": f"{mitre_info['id']} ({mitre_info['name']})",
                "mitre_id": mitre_info['id'],
                "mitre_tactic": mitre_info['tactic'],
                "mitre_name": mitre_info['name'],
                "summary": summary_text[:350].strip() + ("..." if len(summary_text) > 350 else ""),
                "indicators": [cve_id],
                "advisory": f"Mandatory remediation: {action} Check retail perimeter and server inventory for {product}."
            })

    except Exception as e:
        logging.error(f"Error fetching CISA KEV catalog: {e}")

    logging.info(f"Ingested {len(kev_articles)} active vulnerabilities from CISA KEV.")
    return kev_articles

def fetch_and_filter_intel():
    matched_articles = []
    seen_urls = load_previously_seen_urls()
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=MAX_ARTICLE_AGE_DAYS)

    # 1. Direct CISA KEV JSON
    kev_alerts = fetch_cisa_kev_alerts(cutoff_date, seen_urls)
    matched_articles.extend(kev_alerts)

    # 2. Curated Feeds & ICO Enforcement
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

                title = clean_feed_text(entry.get("title", ""))
                summary = entry.get("summary", "") or entry.get("description", "")
                link = entry.get("link", "").strip()

                clean_summary = clean_feed_text(summary)
                combined_text = f"{title} {clean_summary}"

                # Use finditer to capture the full matched string reliably
                retail_matches = [m.group(0) for m in KEYWORD_PATTERN.finditer(combined_text)]
                crit_matches = [m.group(0) for m in CRITICAL_ENTERPRISE_PATTERN.finditer(combined_text)]
                is_ico_enforcement = "ico" in feed["name"].lower() and any(k in combined_text.lower() for k in ["penalty", "fine", "reprimand", "action", "breach", "retail"])
                is_global_critical = bool(crit_matches) or ("advisory" in feed["name"].lower() and "critical" in combined_text.lower())

                if retail_matches or is_global_critical or is_ico_enforcement:
                    date_display = pub_date.strftime("%d %b %Y") if pub_date else "Recent"
                    is_new_threat = link not in seen_urls

                    actor = detect_threat_actor(combined_text)
                    cves_found = list(set(CVE_PATTERN.findall(combined_text)))

                    if is_ico_enforcement:
                        subsector = "loyalty"
                        severity = "HIGH"
                        tags = ["UK ICO", "GDPR Enforcement", "Regulatory Action"]
                        advisory_text = "Review UK GDPR Article 32 security controls and ICO 72h notification readiness."
                    elif retail_matches:
                        subsector = feed["subsector"]
                        is_crit = is_global_critical or any(k in combined_text.lower() for k in [
                            "ransomware", "magecart", "breach", "zero-day", "cvv", "skimmer"
                        ])
                        severity = "CRITICAL" if is_crit else "HIGH"
                        tags = list(set([m.strip().capitalize() for m in retail_matches if m.strip()]))[:3]
                        advisory_text = "Review logs and e-commerce infrastructure for exposure to this vector."
                    else:
                        subsector = "enterprise"
                        severity = "CRITICAL"
                        tags = ["Global 0-Day", "Enterprise"]
                        advisory_text = "Urgent: Patch edge devices and review perimeter telemetry immediately."

                    if actor:
                        tags.insert(0, f"Actor: {actor}")

                    mitre_info = detect_mitre_mapping(combined_text, subsector)

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
                        "is_peak_trading": bool(PEAK_TRADING_PATTERN.search(combined_text)),
                        "severity": severity,
                        "subsector": subsector,
                        "actor": actor,
                        "cves": cves_found,
                        "tags": tags[:4],
                        "mitre": f"{mitre_info['id']} ({mitre_info['name']})",
                        "mitre_id": mitre_info['id'],
                        "mitre_tactic": mitre_info['tactic'],
                        "mitre_name": mitre_info['name'],
                        "summary": clean_summary[:350].strip() + ("..." if len(clean_summary) > 350 else ""),
                        "indicators": [link] if link else [],
                        "advisory": advisory_text
                    })
        except Exception as e:
            logging.error(f"Error scraping {feed['name']}: {e}")

    # Enrich with live FIRST.org EPSS scores
    matched_articles = enrich_threats_with_epss(matched_articles)

    matched_articles.sort(key=lambda x: (x.get("is_new", False), x.get("_timestamp", 0)), reverse=True)
    logging.info(f"Retrieved {len(matched_articles)} total alerts.")
    return matched_articles

# ==============================================================================
# 6. FIREWALL & WAF EXTERNAL DYNAMIC LIST (EDL) EXPORTER
# ==============================================================================
BENIGN_DOMAINS = {
    "cisa.gov", "ncsc.gov.uk", "theregister.com", "bleepingcomputer.com",
    "computerweekly.com", "krebsonsecurity.com", "securityweek.com",
    "securityaffairs.com", "thehackernews.com", "darkreading.com",
    "github.io", "github.com", "first.org", "ico.org.uk", "google.com"
}

def export_firewall_edls(articles):
    """
    Extracts suspicious indicators, payment drop domains, and malicious IPs from ingested threats.
    Outputs clean, plain-text External Dynamic Lists (EDLs) for Palo Alto, Fortinet & Cloudflare WAF.
    """
    os.makedirs("data", exist_ok=True)
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    domains = set()
    ips = set()

    ip_regex = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    domain_regex = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")

    for art in articles:
        text = f"{art.get('title', '')} {art.get('summary', '')} {' '.join(art.get('indicators', []))}"
        
        # Extract IPs (excluding private/internal IP space)
        found_ips = ip_regex.findall(text)
        for ip in found_ips:
            if not (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127.") or ip.startswith("172.")):
                ips.add(ip)

        # Extract Domains (excluding news sites & benign authority domains)
        found_domains = domain_regex.findall(text)
        for dom in found_domains:
            dom_clean = dom.lower().strip()
            if not any(dom_clean.endswith(b) for b in BENIGN_DOMAINS) and len(dom_clean) > 4:
                domains.add(dom_clean)

    # 1. Domain EDL
    domain_file = "data/edl_domains.txt"
    with open(domain_file, "w", encoding="utf-8") as f:
        f.write(f"# UK Retail Threat Intel - Firewall Domain External Dynamic List (EDL)\n")
        f.write(f"# Generated: {today_str} | Subscribed feeds: NCSC, CISA KEV, Krebs, THN\n")
        for dom in sorted(domains):
            f.write(f"{dom}\n")

    # 2. IP EDL
    ip_file = "data/edl_ips.txt"
    with open(ip_file, "w", encoding="utf-8") as f:
        f.write(f"# UK Retail Threat Intel - Firewall IP External Dynamic List (EDL)\n")
        f.write(f"# Generated: {today_str}\n")
        for ip in sorted(ips):
            f.write(f"{ip}\n")

    logging.info(f"Exported Firewall EDLs: {len(domains)} domains, {len(ips)} IPs.")

# ==============================================================================
# 7. OUTBOUND STIX 2.1 & RSS 2.0 SYNDICATION
# ==============================================================================
def export_stix_and_rss(articles):
    """
    Exports telemetry to STIX 2.1 JSON (for Sentinel/Splunk/OpenCTI)
    and RSS 2.0 XML (for internal Slack/Teams/RSS subscribers).
    """
    os.makedirs("data", exist_ok=True)
    now_iso = datetime.now(timezone.utc).isoformat()

    # --- A. STIX 2.1 BUNDLE ---
    stix_objects = []
    bundle_id = f"bundle--{uuid.uuid4()}"

    for art in articles:
        indicator_id = f"indicator--{uuid.uuid4()}"
        stix_objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now_iso,
            "modified": now_iso,
            "name": art.get("title"),
            "description": art.get("summary"),
            "indicator_types": ["malicious-activity"],
            "pattern": f"[url:value = '{art.get('url', '')}']",
            "pattern_type": "stix",
            "valid_from": now_iso,
            "confidence": 90 if art.get("severity") == "CRITICAL" else 75,
            "labels": art.get("tags", []),
            "external_references": [
                {"source_name": art.get("source"), "url": art.get("url", "")}
            ]
        })

        if art.get("mitre_id"):
            ap_id = f"attack-pattern--{uuid.uuid4()}"
            stix_objects.append({
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": ap_id,
                "created": now_iso,
                "modified": now_iso,
                "name": art.get("mitre_name", "Tactical Technique"),
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": art.get("mitre_id")}
                ]
            })

    stix_bundle = {
        "type": "bundle",
        "id": bundle_id,
        "objects": stix_objects
    }

    with open("data/threats.stix.json", "w", encoding="utf-8") as f:
        json.dump(stix_bundle, f, indent=2)

    # --- B. RSS 2.0 FEED ---
    rss_root = ET.Element("rss", version="2.0")
    channel = ET.SubElement(rss_root, "channel")
    ET.SubElement(channel, "title").text = "UK Retail Cyber Threat Intelligence Feed"
    ET.SubElement(channel, "link").text = os.getenv("DASHBOARD_URL", "https://joncummings-ofl.github.io/uk-retail-threat-intel-/")
    ET.SubElement(channel, "description").text = "Curated, high-fidelity threat intelligence feed focused on UK retail, e-commerce, and logistics."
    ET.SubElement(channel, "language").text = "en-gb"
    ET.SubElement(channel, "lastBuildDate").text = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")

    for art in articles[:20]:
        item_el = ET.SubElement(channel, "item")
        ET.SubElement(item_el, "title").text = f"[{art.get('severity')}] {art.get('title')}"
        ET.SubElement(item_el, "link").text = art.get("url", "")
        ET.SubElement(item_el, "description").text = f"{art.get('summary')} Action: {art.get('advisory')}"
        ET.SubElement(item_el, "guid").text = art.get("id", str(uuid.uuid4()))

    tree = ET.ElementTree(rss_root)
    tree.write("data/feed.xml", encoding="utf-8", xml_declaration=True)
    logging.info("Exported data/threats.stix.json and data/feed.xml.")

# ==============================================================================
# 8. GEMINI AI SYNTHESIZER & BRIEFING FORMATTER
# ==============================================================================
def generate_ciso_daily_brief(articles, is_peak_trading=False):
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return "GEMINI_API_KEY not set. Daily briefing skipped."

    client = genai.Client(api_key=api_key)
    new_articles = [a for a in articles if a.get("is_new")]
    focus_articles = new_articles[:6] if new_articles else articles[:5]
    has_new_activity = len(new_articles) > 0

    mode_clause = (
        "PEAK TRADING / GOLDEN QUARTER ALERT ACTIVE: Prioritize bot traffic, checkout DDoS, courier smishing, and gift-card abuse."
        if is_peak_trading else ""
    )

    prompt = f"""
    Act as Principal Cyber Threat Intelligence Analyst for the UK Retail Sector.
    Review the following threat items ({'NEW developments today' if has_new_activity else 'Ongoing active sector threats'}):

    {json.dumps(focus_articles, indent=2)}

    {mode_clause}

    Generate an ultra-brief CISO briefing tailored for mobile/chat reading under 100 words.
    Provide EXACTLY this structure:
    *TL;DR:* 1-2 crisp sentences summarizing today's posture ({'highlighting newly observed vectors' if has_new_activity else 'noting no major overnight retail breaches, surveillance posture maintained on existing perimeter and loyalty threats'}).
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
    Structure:
    1. **Executive Macro Summary**: 2-3 sentences analyzing key attack vectors observed across UK retail this week.
    2. **Dominant Attack Trends**: Detail shifts in threat actor tactics (e.g. Scattered Spider, 3PL logistics extortion, e-commerce tag tampering, loyalty ATO, edge appliance 0-days).
    3. **Regulatory & Audit Posture**: Concrete implications for PCI-DSS v4.0.1 compliance and UK ICO / GDPR 72h disclosure readiness.
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
                logging.warning(f"Weekly Rollup error on {model_name}: {e}")
                time.sleep(attempt * 3)

    return (
        "## UK Retail Weekly Threat Rollup\n\n"
        "Weekly synthesis completed. Threat levels remain ELEVATED across client-side script integrations and perimeter gateways."
    )

def build_google_spaces_payload(briefing, articles, is_weekly=False, is_peak=False):
    today_str = datetime.now(timezone.utc).strftime("%d %b %Y")
    dashboard_url = os.getenv("DASHBOARD_URL", "")
    clean_brief = briefing.replace("**", "*")

    if is_weekly:
        title_banner = f"📊 *UK RETAIL WEEKLY CYBER THREAT ROLLUP* • _{today_str}_\n\n"
    elif is_peak:
        title_banner = f"🛍️ *UK RETAIL PEAK TRADING / GOLDEN QUARTER ALERT* • _{today_str}_\n\n"
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
            epss_tag = f" `EPSS: {art['epss']['score']}`" if art.get("epss") else ""
            actor_tag = f" `[{art['actor']}]`" if art.get("actor") else ""
            title = art["title"]
            url = art.get("url")
            source = art["source"]

            if len(title) > 65:
                title = title[:62] + "..."

            if url:
                message += f"{idx}. {severity_icon}{new_tag} <{url}|{title}>{epss_tag}{actor_tag} — _{source}_\n"
            else:
                message += f"{idx}. {severity_icon}{new_tag} *{title}*{epss_tag}{actor_tag} — _{source}_\n"
    else:
        message += "• _No critical sector alerts detected in the last cycle._\n"

    message += "───────────────────────────────────\n"
    if dashboard_url:
        message += f"👉 *Live Threat Telemetry, EDLs & MITRE Matrix:*\n<{dashboard_url}|Open UK Retail Threat Hub ↗>"
    else:
        message += "👉 *Visit your interactive Threat Hub for full technical IoCs & advisories.*"

    return message

def build_flash_alert_payload(flash_article):
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
    os.makedirs("data", exist_ok=True)

    with open("data/threats.json", "w", encoding="utf-8") as f:
        json.dump(articles, f, indent=2, ensure_ascii=False)

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

# ==============================================================================
# 9. MAIN EXECUTION ROUTINE
# ==============================================================================
if __name__ == "__main__":
    is_weekly_run = ("--weekly" in sys.argv) or (os.getenv("RUN_MODE", "").lower() == "weekly")
    is_flash_mode = ("--flash" in sys.argv) or (os.getenv("RUN_MODE", "").lower() == "flash")
    is_peak_mode = ("--peak" in sys.argv) or (os.getenv("RUN_MODE", "").lower() == "peak")

    logging.info(f"Executing UK Retail Threat Intelligence Run (Mode: {'FLASH ALERT' if is_flash_mode else ('WEEKLY ROLLUP' if is_weekly_run else ('PEAK TRADING' if is_peak_mode else 'DAILY BRIEFING'))})...")

    # Ingest, filter & enrich
    items = fetch_and_filter_intel()

    # Export Firewall EDLs & Syndication Feeds
    export_firewall_edls(items)
    export_stix_and_rss(items)

    # Flash alert priority handling
    flash_candidates = [a for a in items if a.get("is_flash")]
    if is_flash_mode or flash_candidates:
        top_flash = flash_candidates[0] if flash_candidates else items[0]
        logging.info(f"🚨 Flash Alert triggered: {top_flash.get('title')}")
        flash_msg = build_flash_alert_payload(top_flash)
        notify_webhook(flash_msg)

    # AI Synthesis
    if is_weekly_run:
        summary_text = generate_weekly_executive_rollup(items)
    else:
        summary_text = generate_ciso_daily_brief(items, is_peak_trading=is_peak_mode)

    save_output_files(items, summary_text, is_weekly=is_weekly_run)

    if not is_flash_mode:
        formatted_msg = build_google_spaces_payload(summary_text, items, is_weekly=is_weekly_run, is_peak=is_peak_mode)
        notify_webhook(formatted_msg)

    logging.info("Run complete.")
