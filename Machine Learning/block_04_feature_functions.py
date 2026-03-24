# ============================================================
# BLOCK 4 — Define URL Feature Extraction Functions
#           (25 features, no network requests needed)
# ============================================================
#
# Feature groups:
#   Structural (1–12) : length, dots, HTTPS, IP, special chars
#   Semantic  (13–20) : phishing keywords, brand spoofing, free TLDs
#   Entropy   (21–22) : Shannon entropy, randomness detection
#   DGA       (23–25) : Domain Generation Algorithm detection
# ============================================================

# ── Keyword pools ─────────────────────────────────────────────────
SUSPICIOUS_DOMAIN_KW = [
    "crypto", "wallet", "defi", "nft", "token", "eth", "btc", "sol", "bnb",
    "web3", "airdrop", "blockchain", "metamask", "ledger", "trezor", "uniswap",
    "pancake", "opensea", "dex", "swap", "verify", "login-secure",
    "secure-login", "account-verify", "account-update", "billing-update",
    "recover", "unlock", "restore", "suspended", "authenticate", "tracking",
    "delivery-confirm", "parcel-verify", "tax-refund", "gov-portal",
]
SUSPICIOUS_PATH_KW = [
    "wallet/connect", "wallet/verify", "airdrop/claim", "nft/claim",
    "crypto/verify", "defi/connect", "account/suspended", "account/locked",
    "security-alert", "unusual-activity", "password/reset", "password-reset",
    "billing/update", "card/update", "card/verify", "kyc/verify", "identity/verify",
]
BRAND_NAMES = [
    "paypal", "amazon", "google", "microsoft", "apple", "facebook", "netflix",
    "instagram", "whatsapp", "twitter", "linkedin", "dropbox", "adobe",
    "ebay", "walmart", "chase", "bankofamerica", "wellsfargo", "citibank",
    "coinbase", "binance", "metamask", "trustwallet", "ledger", "opensea",
    "fedex", "ups", "usps", "dhl", "royalmail", "steam", "roblox", "epic",
    "spotify", "discord", "zoom", "slack", "shopify", "stripe",
]
FREE_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".online",
    ".site", ".space", ".fun", ".pw", ".win", ".click", ".download", ".link",
}

# ── Entropy / gibberish helpers ───────────────────────────────────
def _entropy(s):
    """Shannon entropy — high value = random/gibberish characters"""
    if not s:
        return 0.0
    c = Counter(s)
    t = len(s)
    return round(-sum((v / t) * math.log2(v / t) for v in c.values()), 4)


def _consonant_ratio(s):
    """Ratio of consonants — high = no vowels = gibberish domain"""
    if not s:
        return 0.0
    return round(
        sum(1 for c in s if c.isalpha() and c not in "aeiou") / len(s), 4
    )


def _is_gibberish(s):
    """
    Returns 1 if string looks DGA-generated.
    Catches patterns like: servcaccntwebappaoiuhyswerdg, dtuiertgdfhfgdj
    """
    if len(s) < 4:
        return 0
    cr = _consonant_ratio(s)
    en = _entropy(s)
    if cr > 0.68 and en > 2.8:   return 1   # long random consonant string
    if cr > 0.75 and en > 2.0:   return 1   # very consonant-heavy
    if len(s) > 12 and en > 3.5: return 1   # very long high-entropy label
    return 0


# ── MAIN: extract 25 features from one URL ────────────────────────
def extract_features(url):
    """
    Extract 25 numerical features from a URL string.
    Returns a list of numbers — no network requests needed.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return [0] * 25

    scheme   = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()
    path     = (parsed.path or "").lower()
    query    = (parsed.query or "").lower()

    # ── GROUP 1: Structural features (1–12) ──────────────────────
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
    after_scheme       = url.split("://", 1)[-1] if "://" in url else url
    double_slash_count = after_scheme.count("//")
    digit_count        = sum(c.isdigit() for c in url)

    # ── GROUP 2: Semantic features (13–20) ───────────────────────
    domain_body = re.sub(
        r"\.(com|net|org|io|co|xyz|tk|ml|top|online|site|info|biz|us|uk|in"
        r"|ru|cn|br|au|de|fr|jp|club|space|fun|pw|win|click|download|link"
        r"|live|shop|store|ltd|inc|group|cc|ws|mobi|tv|me|app|dev)"
        r"(\.[a-z]{2,3})?$",
        "", hostname,
    )
    domain_body = re.sub(r"^www\d*\.", "", domain_body)

    suspicious_kw_in_domain = int(any(kw in domain_body for kw in SUSPICIOUS_DOMAIN_KW))
    brand_in_domain         = int(any(b in domain_body for b in BRAND_NAMES))
    free_tld                = int(any(hostname.endswith(t) for t in FREE_TLDS))
    domain_length           = len(hostname)
    domain_digit_ratio      = round(sum(c.isdigit() for c in hostname) / len(hostname), 4) if hostname else 0.0
    full_pq                 = path + "?" + query
    suspicious_kw_in_path   = int(any(kw in full_pq for kw in SUSPICIOUS_PATH_KW))
    hyphen_count_domain     = hostname.count("-")
    brand_in_subdomain      = 0
    if len(parts) > 2:
        sub_str = ".".join(parts[:-2])
        brand_in_subdomain = int(any(b in sub_str for b in BRAND_NAMES))

    # ── GROUP 3: Entropy features (21–22) ────────────────────────
    domain_entropy   = _entropy(domain_body)
    is_random_domain = int(_is_gibberish(domain_body))

    # ── GROUP 4: DGA detection (23–25) ───────────────────────────
    subdomain_str = ".".join(parts[:-2]) if len(parts) > 2 else ""
    sub_labels    = subdomain_str.split(".") if subdomain_str else []
    longest_sub   = max(sub_labels, key=len) if sub_labels else ""

    subdomain_is_gibberish = int(_is_gibberish(longest_sub)) if longest_sub else 0
    all_labels             = hostname.split(".")
    longest_label_len      = max(len(lbl) for lbl in all_labels) if all_labels else 0
    domain_label           = parts[-2] if len(parts) >= 2 else ""
    both_gibberish         = int(
        bool(longest_sub) and _is_gibberish(longest_sub) and _is_gibberish(domain_label)
    )

    return [
        # Structural
        url_length, dot_count, has_at_symbol, has_hyphen,
        subdomain_count, is_https, path_length, query_length,
        has_ip_address, special_char_count, double_slash_count, digit_count,
        # Semantic
        suspicious_kw_in_domain, brand_in_domain, free_tld,
        domain_length, domain_digit_ratio, suspicious_kw_in_path,
        hyphen_count_domain, brand_in_subdomain,
        # Entropy
        domain_entropy, is_random_domain,
        # DGA
        subdomain_is_gibberish, longest_label_len, both_gibberish,
    ]


FEATURE_NAMES = [
    # Structural (1–12)
    "url_length", "dot_count", "has_at_symbol", "has_hyphen",
    "subdomain_count", "is_https", "path_length", "query_length",
    "has_ip_address", "special_char_count", "double_slash_count", "digit_count",
    # Semantic (13–20)
    "suspicious_kw_in_domain", "brand_in_domain", "free_tld",
    "domain_length", "domain_digit_ratio", "suspicious_kw_in_path",
    "hyphen_count_domain", "brand_in_subdomain",
    # Entropy (21–22)
    "domain_entropy", "is_random_domain",
    # DGA (23–25)
    "subdomain_is_gibberish", "longest_label_len", "both_gibberish",
]


# ── Demo ──────────────────────────────────────────────────────────
print(f"✅ Feature extractor ready: {len(FEATURE_NAMES)} features")
print()
demo_urls = [
    ("https://paypal-verify.xyz/login.php",         "PHISHING"),
    ("http://192.168.1.1/login",                    "PHISHING"),
    ("https://deficryptowallets.com/",              "PHISHING"),
    ("https://servcacc.dtuiertg.com/?x",            "PHISHING"),
    ("https://www.paypal.com/signin",               "LEGIT"),
    ("https://google.com/search?q=test",            "LEGIT"),
]
print(f"{'URL':<48} {'Label':<10} {'len':>5} {'https':>5} {'entropy':>8} {'gibber':>7}")
print("-" * 88)
for url, label in demo_urls:
    f = extract_features(url)
    print(f"{url[:47]:<48} {label:<10} {f[0]:>5} {f[5]:>5} {f[20]:>8.3f} {f[24]:>7}")
