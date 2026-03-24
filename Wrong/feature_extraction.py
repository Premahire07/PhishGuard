import re, math
from collections import Counter
from urllib.parse import urlparse

TRUSTED_DOMAINS = {
    "udemy.com","coursera.org","edx.org","khanacademy.org","duolingo.com",
    "skillshare.com","pluralsight.com","udacity.com","brilliant.org",
    "codecademy.com","freecodecamp.org","w3schools.com",
    "google.com","youtube.com","gmail.com","googlemail.com",
    "microsoft.com","office.com","live.com","outlook.com","bing.com",
    "apple.com","icloud.com","itunes.com",
    "amazon.com","amazonaws.com","amazon.co.uk","amazon.in",
    "facebook.com","instagram.com","whatsapp.com","messenger.com",
    "twitter.com","x.com","t.co","linkedin.com",
    "slack.com","zoom.us","discord.com","telegram.org",
    "github.com","gitlab.com","bitbucket.org","stackoverflow.com",
    "npmjs.com","pypi.org","docker.com","kubernetes.io",
    "cloudflare.com","digitalocean.com","heroku.com","vercel.com","netlify.com",
    "azure.com","cloud.google.com",
    "paypal.com","stripe.com","shopify.com","etsy.com","ebay.com",
    "walmart.com","target.com","bestbuy.com",
    "flipkart.com","myntra.com","paytm.com","phonepe.com",
    "chase.com","bankofamerica.com","wellsfargo.com","citibank.com",
    "coinbase.com","binance.com","kraken.com","metamask.io",
    "reddit.com","pinterest.com","snapchat.com","tiktok.com","twitch.tv",
    "netflix.com","spotify.com","hulu.com","disneyplus.com",
    "nytimes.com","bbc.com","bbc.co.uk","cnn.com","reuters.com",
    "bloomberg.com","theguardian.com","wsj.com","forbes.com",
    "techcrunch.com","wired.com","theverge.com","arstechnica.com",
    "ndtv.com","timesofindia.com","thehindu.com","hindustantimes.com",
    "wikipedia.org","wikimedia.org","archive.org","quora.com","medium.com",
    "notion.so","airtable.com","trello.com","asana.com","figma.com",
    "canva.com","adobe.com","dropbox.com","box.com",
    "wordpress.com","wix.com","squarespace.com","godaddy.com",
    "protonmail.com","zoho.com","mailchimp.com",
    "salesforce.com","hubspot.com","zendesk.com",
    "uber.com","lyft.com","airbnb.com","booking.com","expedia.com",
    "doordash.com","grubhub.com","zomato.com","swiggy.com",
    "steampowered.com","epicgames.com","roblox.com",
    "espn.com","nba.com","nfl.com","cricbuzz.com",
    "imdb.com","webmd.com","mayoclinic.org","nih.gov","cdc.gov","who.int",
    "nasa.gov","irs.gov","usa.gov","gov.uk","nhs.uk",
    "irctc.co.in","sbi.co.in","hdfcbank.com","icicibank.com",
    "axisbank.com","kotak.com","makemytrip.com","naukri.com",
    "bit.ly","t.co","goo.gl","ow.ly","tinyurl.com","is.gd","rb.gy",
}

SUSPICIOUS_DOMAIN_KW = [
    "crypto","wallet","defi","nft","token","eth","btc","sol","bnb","web3",
    "airdrop","blockchain","metamask","ledger","trezor","uniswap","pancake",
    "opensea","dex","swap","verify","login-secure","secure-login",
    "account-verify","account-update","billing-update","recover","unlock",
    "restore","suspended","authenticate","tracking","delivery-confirm",
    "parcel-verify","tax-refund","gov-portal",
]

SUSPICIOUS_PATH_KW = [
    "wallet/connect","wallet/verify","airdrop/claim","nft/claim",
    "crypto/verify","defi/connect","account/suspended","account/locked",
    "security-alert","unusual-activity","password/reset","password-reset",
    "billing/update","card/update","card/verify","kyc/verify","identity/verify",
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

def _get_domain_root(hostname):
    parts = hostname.lower().split(".")
    if len(parts) >= 3 and parts[-2] in ("co","com","org","net","gov","ac","edu"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname

def is_trusted(hostname):
    return _get_domain_root(hostname) in TRUSTED_DOMAINS

def _entropy(s):
    if not s: return 0.0
    c = Counter(s); t = len(s)
    return round(-sum((v/t)*math.log2(v/t) for v in c.values()), 4)

def _consonant_ratio(s):
    if not s: return 0.0
    return round(sum(1 for c in s if c.isalpha() and c not in 'aeiou') / len(s), 4)

def _is_gibberish(s):
    """True if string looks like DGA / randomly generated text."""
    if len(s) < 4: return 0
    cr = _consonant_ratio(s)
    en = _entropy(s)
    if cr > 0.68 and en > 2.8: return 1   # long random consonant string
    if cr > 0.75 and en > 2.0: return 1   # very consonant-heavy
    if len(s) > 12 and en > 3.5: return 1 # very long high-entropy label
    return 0

def extract_features(url: str) -> list:
    try:
        parsed = urlparse(url)
    except Exception:
        return [0] * 25

    scheme   = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()
    path     = (parsed.path or "").lower()
    query    = (parsed.query or "").lower()

    if is_trusted(hostname):
        return [len(url), url.count("."), 0, 0, 0,
                1, len(path), 0, 0, 0, 0, 0,
                0, 0, 0, len(hostname), 0.0, 0, 0, 0,
                0.0, 0, 0, 0, 0]

    # ── Features 1–12: Structural ────────────────────────────────────
    url_length         = len(url)
    dot_count          = url.count(".")
    has_at_symbol      = 1 if "@" in url else 0
    has_hyphen         = 1 if "-" in hostname else 0
    parts              = hostname.split(".") if hostname else []
    subdomain_count    = max(0, len(parts) - 2)
    is_https           = 1 if scheme == "https" else 0
    path_length        = len(path)
    query_length       = len(query)
    has_ip_address     = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0
    special_char_count = sum(c in set("%=&#!") for c in url)
    after_scheme       = url.split("://",1)[-1] if "://" in url else url
    double_slash_count = after_scheme.count("//")
    digit_count        = sum(c.isdigit() for c in url)

    # ── Features 13–20: Semantic ─────────────────────────────────────
    domain_body = re.sub(
        r"\.(com|net|org|io|co|xyz|tk|ml|top|online|site|info|biz|us|uk|in"
        r"|ru|cn|br|au|de|fr|jp|club|space|fun|pw|win|click|download|link"
        r"|live|shop|store|ltd|inc|group|cc|ws|mobi|tv|me|ly|gl|gg|app|dev"
        r"|ai|vc|so)(\.[a-z]{2,3})?$", "", hostname)
    domain_body = re.sub(r"^www\d*\.", "", domain_body)

    suspicious_kw_in_domain  = int(any(kw in domain_body for kw in SUSPICIOUS_DOMAIN_KW))
    brand_in_domain          = int(not is_trusted(hostname) and any(b in domain_body for b in BRAND_NAMES))
    free_tld                 = int(any(hostname.endswith(t) for t in FREE_TLDS))
    domain_length            = len(hostname)
    domain_digit_ratio       = round(sum(c.isdigit() for c in hostname)/len(hostname), 4) if hostname else 0.0
    full_pq                  = path + "?" + query
    suspicious_kw_in_path    = int(any(kw in full_pq for kw in SUSPICIOUS_PATH_KW))
    hyphen_count_domain      = hostname.count("-")
    brand_in_subdomain       = 0
    if len(parts) > 2:
        sub_str = ".".join(parts[:-2])
        brand_in_subdomain = int(any(b in sub_str for b in BRAND_NAMES))

    # ── Features 21–22: Entropy / randomness ────────────────────────
    domain_entropy   = _entropy(domain_body)
    is_random_domain = int(_is_gibberish(domain_body))

    # ── Feature 23 (NEW): Subdomain is gibberish ────────────────────
    # Catches: servcaccntwebappaoiuhyswerdg.dtuiertgdfhfgdj.com
    # The SUBDOMAIN is long and random — this is a DGA pattern
    subdomain_str = ".".join(parts[:-2]) if len(parts) > 2 else ""
    # Check the longest subdomain label
    sub_labels = subdomain_str.split(".") if subdomain_str else []
    longest_sub = max(sub_labels, key=len) if sub_labels else ""
    subdomain_is_gibberish = int(_is_gibberish(longest_sub)) if longest_sub else 0

    # ── Feature 24 (NEW): Longest hostname label length ─────────────
    # Normal sites: "www", "mail", "api" (3-6 chars)
    # DGA phishing: "servcaccntwebappaoiuhyswerdg" (28 chars!)
    all_labels = hostname.split(".")
    longest_label_len = max(len(l) for l in all_labels) if all_labels else 0

    # ── Feature 25 (NEW): Both subdomain AND domain are gibberish ────
    # Ultimate DGA signal: when BOTH parts are random
    # servcaccntwebappaoiuhyswerdg (sub) + dtuiertgdfhfgdj (domain) = 100% DGA
    domain_label = parts[-2] if len(parts) >= 2 else ""
    both_gibberish = int(
        _is_gibberish(longest_sub) and _is_gibberish(domain_label)
    ) if longest_sub else 0

    return [
        url_length, dot_count, has_at_symbol, has_hyphen,
        subdomain_count, is_https, path_length, query_length,
        has_ip_address, special_char_count, double_slash_count, digit_count,
        suspicious_kw_in_domain, brand_in_domain, free_tld,
        domain_length, domain_digit_ratio, suspicious_kw_in_path,
        hyphen_count_domain, brand_in_subdomain,
        domain_entropy, is_random_domain,
        subdomain_is_gibberish, longest_label_len, both_gibberish,
    ]

def get_feature_names():
    return [
        "url_length","dot_count","has_at_symbol","has_hyphen",
        "subdomain_count","is_https","path_length","query_length",
        "has_ip_address","special_char_count","double_slash_count","digit_count",
        "suspicious_kw_in_domain","brand_in_domain","free_tld",
        "domain_length","domain_digit_ratio","suspicious_kw_in_path",
        "hyphen_count_domain","brand_in_subdomain",
        "domain_entropy","is_random_domain",
        "subdomain_is_gibberish","longest_label_len","both_gibberish",
    ]
