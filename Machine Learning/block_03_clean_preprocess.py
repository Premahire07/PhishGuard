# ============================================================
# BLOCK 3 — Clean and Preprocess the Dataset
#           (remove duplicates, missing values, bad rows)
# ============================================================

print("=== BEFORE Cleaning ===")
print(f"Total rows       : {len(df_raw):,}")
print(f"Duplicate URLs   : {df_raw['url'].duplicated().sum():,}")
print(f"Missing values   :\n{df_raw.isnull().sum().to_string()}")
print()

# ── Step 1: Drop duplicate URLs ──────────────────────────────────
df = df_raw.drop_duplicates(subset=["url"]).copy()
print(f"After drop_duplicates  : {len(df):,} rows  (removed {len(df_raw)-len(df):,})")

# ── Step 2: Drop any rows with missing / NaN values ──────────────
df = df.dropna()
print(f"After dropna           : {len(df):,} rows")

# ── Step 3: Remove empty or very short URLs ──────────────────────
df = df[df["url"].str.len() >= 10].copy()
print(f"After min-length (≥10) : {len(df):,} rows")

# ── Step 4: Strip whitespace ──────────────────────────────────────
df["url"] = df["url"].str.strip()

# ── Step 5: Reset index ───────────────────────────────────────────
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

print()
print("=== AFTER Cleaning ===")
print(f"Total rows       : {len(df):,}")
print(f"Legitimate (0)   : {(df.label==0).sum():,}")
print(f"Phishing   (1)   : {(df.label==1).sum():,}")
print(f"Missing values   : {df.isnull().sum().sum()}")
print(f"Duplicates       : {df['url'].duplicated().sum()}")
