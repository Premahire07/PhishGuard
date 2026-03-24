import re
from urllib.parse import urlparse

# ══════════════════════════════════════════════════════════════════
# TRUSTED DOMAIN WHITELIST
# These domains are ALWAYS safe — never run ML on them.
# Based on Alexa Top 500 + Cisco Umbrella + Majestic Million
# ══════════════════════════════════════════════════════════════════
TRUSTED_DOMAINS = {
    # Education
    "udemy.com","coursera.org","edx.org","khanacademy.org","duolingo.com",
    "skillshare.com","linkedin.com","pluralsight.com","udacity.com",
    "brilliant.org","codecademy.com","freecodecamp.org","w3schools.com",
    # Tech Giants
    "google.com","youtube.com","gmail.com","googlemail.com",
    "microsoft.com","office.com","live.com","outlook.com","bing.com",
    "apple.com","icloud.com","itunes.com",
    "amazon.com","aws.amazon.com","amazonaws.com",
    "facebook.com","instagram.com","whatsapp.com","messenger.com",
    "twitter.com","x.com","t.co",
    "linkedin.com","slack.com","zoom.us","teams.microsoft.com",
    # Dev / Cloud
    "github.com","gitlab.com","bitbucket.org","stackoverflow.com",
    "npmjs.com","pypi.org","docker.com","kubernetes.io",
    "cloudflare.com","digitalocean.com","heroku.com","vercel.com","netlify.com",
    "azure.com","cloud.google.com",
    # Shopping / Finance
    "paypal.com","stripe.com","shopify.com","etsy.com","ebay.com",
    "walmart.com","target.com","bestbuy.com","amazon.co.uk","amazon.in",
    "flipkart.com","myntra.com","paytm.com","phonepe.com",
    "chase.com","bankofamerica.com","wellsfargo.com","citibank.com",
    "coinbase.com","binance.com","kraken.com",
    # Social / Media
    "reddit.com","discord.com","telegram.org","pinterest.com",
    "snapchat.com","tiktok.com","twitch.tv","netflix.com",
    "spotify.com","hulu.com","disneyplus.com","youtube.com",
    # News
    "nytimes.com","bbc.com","bbc.co.uk","cnn.com","reuters.com",
    "bloomberg.com","theguardian.com","wsj.com","forbes.com",
    "techcrunch.com","wired.com","theverge.com","arstechnica.com",
    "ndtv.com","timesofindia.com","thehindu.com","hindustantimes.com",
    # Search / Info
    "wikipedia.org","wikimedia.org","wolfram.com","wolframalpha.com",
    "archive.org","quora.com","medium.com",
    # Productivity
    "notion.so","airtable.com","trello.com","asana.com",
    "dropbox.com","box.com","onedrive.live.com",
    "figma.com","canva.com","adobe.com",
    # Other top sites
    "wordpress.com","wix.com","squarespace.com","godaddy.com",
    "protonmail.com","tutanota.com","zoho.com","mailchimp.com",
    "salesforce.com","hubspot.com","zendesk.com",
    "uber.com","lyft.com","airbnb.com","booking.com","expedia.com",
    "doordash.com","grubhub.com","zomato.com","swiggy.com",
    "steam.com","steampowered.com","epicgames.com","roblox.com",
    "espn.com","nba.com","nfl.com","cricbuzz.com","iplt20.com",
    "imdb.com","rottentomatoes.com",
    "webmd.com","mayoclinic.org","nih.gov","cdc.gov","who.int",
    "nasa.gov","irs.gov","usa.gov","gov.uk","nhs.uk",
    # Indian sites
    "irctc.co.in","sbi.co.in","hdfcbank.com","icicibank.com",
    "axisbank.com","kotak.com","ola.cab","makemytrip.com",
    "snapdeal.com","naukri.com","indiamart.com","justdial.com",
}

SUSPICIOUS_DOMAIN_KW = [
    "crypto","wallet","defi","nft","token","eth","btc","sol","bnb","web3",
    "airdrop","blockchain","metamask","ledger","trezor","exodus","uniswap",
    "pancake","opensea","dex","swap",
    "verify","login-secure","secure-login","signin-verify",
    "account-verify","account-update","billing-update",
    "recover","unlock","restore","suspended","authenticate",
    "tracking","delivery-confirm","parcel-verify",
    "tax-refund","irs-refund","gov-portal",
]

SUSPICIOUS_PATH_KW = [
    "wallet/connect","wallet/verify","airdrop/claim","nft/claim",
    "crypto/verify","defi/connect",
    "account/suspended","account/locked","account/blocked",
    "security-alert","unusual-activity",
    "password/reset","password-reset",
    "billing/update","card/update","card/verify",
    "kyc/verify","identity/verify",
]

BRAND_NAMES = [
    "paypal","amazon","google","microsoft","apple","facebook","netflix",
    "instagram","whatsapp","twitter","linkedin","dropbox","adobe",
    "ebay","walmart","chase","bankofamerica","wellsfargo","citibank",
    "coinbase","binance","metamask","trustwallet","ledger","opensea",
    "fedex","ups","usps","dhl","royalmail","steam","roblox","epic",
    "spotify","discord","zoom","slack","shopify","stripe",
]

FREE_TLDS = {
    ".tk",".ml",".ga",".cf",".gq",".xyz",".top",".club",".online",
    ".site",".space",".fun",".pw",".win",".click",".download",".link",
}

def _get_domain_root(hostname: str) -> str:
    """Return eTLD+1 root, e.g. 'www.udemy.com' → 'udemy.com'"""
    parts = hostname.lower().split(".")
    if len(parts) >= 2:
        # Handle compound ccTLDs: .co.uk, .co.in, .com.br etc.
        if len(parts) >= 3 and parts[-2] in ("co","com","org","net","gov","ac","edu"):
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return hostname

def is_trusted(hostname: str) -> bool:
    """Return True if hostname belongs to a trusted domain."""
    root = _get_domain_root(hostname)
    return root in TRUSTED_DOMAINS

def extract_features(url: str) -> list:
    try:
        parsed = urlparse(url)
    except Exception:
        return [0] * 20

    scheme   = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()
    path     = (parsed.path or "").lower()
    query    = (parsed.query or "").lower()

    # ── TRUSTED DOMAIN SHORTCUT ─────────────────────────────────────
    # If root domain is trusted, return a feature vector that will
    # always predict SAFE — skips all ML noise for legit sites.
    if is_trusted(hostname):
        return [
            len(url), url.count("."), 0, 0, 0,
            1,           # is_https (trusted sites use HTTPS)
            len(path), 0, 0, 0, 0, 0,
            0, 0, 0,     # no suspicious domain signals
            len(hostname), 0.0,
            0, 0, 0,     # no suspicious path signals
        ]

    # ── Feature 1–12: Original structural features ─────────────────
    url_length         = len(url)
    dot_count          = url.count(".")
    has_at_symbol      = 1 if "@" in url else 0
    has_hyphen         = 1 if "-" in hostname else 0
    parts              = hostname.split(".") if hostname else []
    subdomain_count    = max(0, len(parts) - 2)
    is_https           = 1 if scheme == "https" else 0
    path_length        = len(path)
    query_length       = len(query)
    ip_pat             = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    has_ip_address     = 1 if ip_pat.match(hostname) else 0
    special_chars      = set("%=&#!")
    special_char_count = sum(c in special_chars for c in url)
    after_scheme       = url.split("://", 1)[-1] if "://" in url else url
    double_slash_count = after_scheme.count("//")
    digit_count        = sum(c.isdigit() for c in url)

    # ── Feature 13: Suspicious keyword in DOMAIN BODY only ─────────
    # Strip TLD and www before checking — avoids UTM params triggering this
    domain_body = re.sub(
        r"\.(com|net|org|io|co|xyz|tk|ml|top|online|site|info|biz|us|uk|in"
        r"|ru|cn|br|au|de|fr|jp|club|space|fun|pw|win|click|download|link"
        r"|live|shop|store|ltd|inc|group|cc|ws|mobi|tv|me|ly|gl|gg|app|dev"
        r"|ai|vc|so)(\.[a-z]{2,3})?$", "", hostname)
    domain_body = re.sub(r"^www\d*\.", "", domain_body)

    suspicious_kw_in_domain = 0
    for kw in SUSPICIOUS_DOMAIN_KW:
        if kw in domain_body:
            suspicious_kw_in_domain = 1
            break

    # ── Feature 14: Brand name in domain (not an official domain) ───
    brand_in_domain = 0
    for brand in BRAND_NAMES:
        if brand in domain_body and not is_trusted(hostname):
            brand_in_domain = 1
            break

    # ── Feature 15: Free / abused TLD ───────────────────────────────
    free_tld = 0
    for tld in FREE_TLDS:
        if hostname.endswith(tld):
            free_tld = 1
            break

    # ── Feature 16: Domain length ────────────────────────────────────
    domain_length = len(hostname)

    # ── Feature 17: Digit ratio in domain ───────────────────────────
    domain_digit_ratio = (
        round(sum(c.isdigit() for c in hostname) / len(hostname), 4)
        if hostname else 0.0
    )

    # ── Feature 18: Suspicious keyword in PATH (strict list) ────────
    # Use full path+query phrases, not single words like "login"
    full_path_query = path + "?" + query
    suspicious_kw_in_path = 0
    for kw in SUSPICIOUS_PATH_KW:
        if kw in full_path_query:
            suspicious_kw_in_path = 1
            break

    # ── Feature 19: Hyphen count in domain ──────────────────────────
    hyphen_count_domain = hostname.count("-")

    # ── Feature 20: Brand name in subdomain ─────────────────────────
    brand_in_subdomain = 0
    if len(parts) > 2:
        sub_str = ".".join(parts[:-2])
        for brand in BRAND_NAMES:
            if brand in sub_str:
                brand_in_subdomain = 1
                break

    return [
        url_length, dot_count, has_at_symbol, has_hyphen,
        subdomain_count, is_https, path_length, query_length,
        has_ip_address, special_char_count, double_slash_count,
        digit_count,
        suspicious_kw_in_domain, brand_in_domain, free_tld,
        domain_length, domain_digit_ratio, suspicious_kw_in_path,
        hyphen_count_domain, brand_in_subdomain,
    ]


def get_feature_names():
    return [
        "url_length","dot_count","has_at_symbol","has_hyphen",
        "subdomain_count","is_https","path_length","query_length",
        "has_ip_address","special_char_count","double_slash_count",
        "digit_count",
        "suspicious_kw_in_domain","brand_in_domain","free_tld",
        "domain_length","domain_digit_ratio","suspicious_kw_in_path",
        "hyphen_count_domain","brand_in_subdomain",
    ]
