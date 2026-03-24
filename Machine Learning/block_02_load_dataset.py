# ============================================================
# BLOCK 2 — Load the Dataset into Python using pandas
# ============================================================
# If you have a real CSV file, just do:
#   df_raw = pd.read_csv("your_dataset.csv")
#
# Here we generate 50,000 URLs (25k legit + 25k phishing)
# to simulate a real-world phishing dataset.
# ============================================================

import random
import string

random.seed(42)

# ── Legitimate domain pool ────────────────────────────────────────
LEGIT_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
    "reddit.com", "twitter.com", "instagram.com", "linkedin.com", "github.com",
    "microsoft.com", "apple.com", "netflix.com", "paypal.com", "ebay.com",
    "stackoverflow.com", "udemy.com", "coursera.org", "spotify.com", "zoom.us",
    "dropbox.com", "slack.com", "discord.com", "twitch.tv", "shopify.com",
    "nytimes.com", "bbc.com", "cnn.com", "reuters.com", "bloomberg.com",
    "flipkart.com", "paytm.com", "ndtv.com", "timesofindia.com", "hdfcbank.com",
    "sbi.co.in", "irctc.co.in", "zomato.com", "swiggy.com", "icicibank.com",
    "coinbase.com", "binance.com", "stripe.com", "adobe.com", "salesforce.com",
    "oracle.com", "ibm.com", "cisco.com", "intel.com", "nvidia.com",
]
LEGIT_PATHS = [
    "/", "/home", "/about", "/contact", "/products", "/services", "/blog",
    "/login", "/signup", "/dashboard", "/profile", "/search", "/help",
    "/docs", "/terms", "/privacy", "/careers", "/pricing", "/features",
    "/news", "/support", "/faq", "/download", "/api", "/settings",
]
LEGIT_SUBS = ["", "www", "m", "app", "mail", "shop", "docs", "blog", "support"]

# ── Phishing URL pools ────────────────────────────────────────────
PHISHING_BRANDS = [
    "paypal", "amazon", "google", "microsoft", "apple", "facebook", "netflix",
    "instagram", "coinbase", "binance", "metamask", "chase", "bankofamerica",
    "wellsfargo", "citibank", "fedex", "ups", "usps", "dhl", "steam", "ebay",
    "walmart", "target", "linkedin", "dropbox", "adobe", "spotify", "discord",
    "irs", "gov", "hmrc", "paytm", "hdfcbank", "sbi", "irctc", "flipkart",
]
PHISHING_TLDS = [
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".club", ".online",
    ".site", ".space", ".fun", ".pw", ".cc", ".win", ".click", ".link",
]
PHISHING_KW = [
    "secure", "verify", "update", "confirm", "account", "login", "signin",
    "alert", "suspended", "locked", "recover", "urgent", "support", "banking",
    "payment", "refund", "tracking", "delivery", "tax", "portal", "wallet",
    "airdrop", "claim", "crypto", "defi", "nft", "token", "auth", "credential",
]
PHISHING_PATHS = [
    "/secure/login.php", "/account/login.php", "/signin/index.php",
    "/verify/account.php", "/update/account.php", "/confirm/identity.php",
    "/account-suspended/", "/password/reset.php", "/wallet/connect",
    "/airdrop/claim.php", "/tracking/", "/delivery/confirm.php",
    "/index.php", "/wp-login.php", "/account/verify.php",
]


def _rstr(n, chars=string.ascii_lowercase + string.digits):
    return "".join(random.choices(chars, k=n))


def _rand_ip():
    return (f"{random.randint(1,254)}.{random.randint(0,254)}"
            f".{random.randint(0,254)}.{random.randint(1,254)}")


def _rng_label(a=8, b=20):
    c = "bcdfghjklmnpqrstvwxyz"
    v = "aeiou"
    n = random.randint(a, b)
    return "".join(random.choice(c if random.random() < 0.72 else v) for _ in range(n))


def make_legit():
    d   = random.choice(LEGIT_DOMAINS)
    sub = random.choice(LEGIT_SUBS)
    p   = random.choice(LEGIT_PATHS)
    h   = f"{sub}.{d}" if sub else d
    sch = "https" if random.random() < 0.93 else "http"
    return f"{sch}://{h}{p}"


def make_phishing():
    s = random.randint(1, 10)
    b = random.choice(PHISHING_BRANDS)
    k = random.choice(PHISHING_KW)
    t = random.choice(PHISHING_TLDS)
    p = random.choice(PHISHING_PATHS)
    if   s == 1: return f"http://{b}-{k}{t}{p}"
    elif s == 2: return f"http://{_rand_ip()}{p}"
    elif s == 3: return f"http://{b}.{_rstr(5)}.{_rstr(4)}.{_rstr(8)}{t}{p}"
    elif s == 4: return f"http://www.{b}.com@{_rstr(10)}{t}{p}"
    elif s == 5:
        look = b.replace("o", "0").replace("l", "1").replace("a", "4")
        return f"http://www.{look}{t}{p}"
    elif s == 6: return f"http://{k}-{b}.{_rstr(12)}{t}/{k}/?token={_rstr(24)}"
    elif s == 7:
        port = random.choice([8080, 1337, 4444, 9090])
        return f"http://{b}-{_rstr(8)}{t}:{port}{p}"
    elif s == 8: return f"http://secure.{b}.com.{_rstr(10)}{t}{p}"
    elif s == 9:
        crypto = random.choice(["metamask", "wallet", "nft", "crypto", "defi", "airdrop"])
        return f"http://{crypto}-{k}.{_rstr(10)}{t}/connect?callback={_rstr(20)}"
    else:
        sub = _rng_label(10, 22)
        dom = _rng_label(8, 14)
        return f"https://{sub}.{dom}.com{p}"


# ── Generate dataset ──────────────────────────────────────────────
N = 25_000
print(f"Generating {N:,} legitimate + {N:,} phishing URLs ...")

legit_urls = [make_legit()    for _ in range(N)]
phish_urls = [make_phishing() for _ in range(N)]

# Real-world edge cases (URLs that are tricky to classify)
edge_phish = [
    "https://deficryptowallets.com/",
    "https://ourlzllc.com/",
    "https://ourlzllc.com/trading",
    "https://servcaccntwebappaoiuhyswerdg.dtuiertgdfhfgdj.com/?yyy",
    "http://paypal.com@phish.xyz/login",
    "https://secure.paypal.com.abc123.tk/kyc",
    "https://cryptfxllc.com/",
    "https://xkjqplmnbvcxzw.rtyuiopasdfgh.com/",
]
edge_legit = [
    "https://www.udemy.com/?utm_source=adwords&utm_campaign=Brand",
    "https://mail.google.com/mail/u/0/",
    "https://coinbase.com/dashboard",
    "https://paypal.com/signin?utm_source=brand",
    "https://metamask.io/download",
]

phish_urls += edge_phish * 200
legit_urls += edge_legit * 200

# ── Build raw dataframe ───────────────────────────────────────────
df_legit  = pd.DataFrame({"url": legit_urls,  "label": 0})
df_phish  = pd.DataFrame({"url": phish_urls,  "label": 1})
df_raw    = pd.concat([df_legit, df_phish], ignore_index=True)

print(f"✅ Dataset loaded: {len(df_raw):,} rows")
print()
print(df_raw.head(6).to_string())
print()
print(df_raw["label"].value_counts())
