# ============================================================
# BLOCK 5 — Convert All URLs into Numerical Features
# ============================================================

print(f"Extracting features from {len(df):,} URLs ...")
t0 = time.time()

feature_rows = df["url"].apply(extract_features).tolist()
features_df  = pd.DataFrame(feature_rows, columns=FEATURE_NAMES)

print(f"✅ Done in {time.time() - t0:.1f}s")
print()
print(f"Feature matrix shape : {features_df.shape}  (rows × features)")
print()
print("Sample — first 5 rows, first 8 features:")
print(features_df[FEATURE_NAMES[:8]].head().to_string())
print()
print("Feature statistics (structural group):")
print(features_df[FEATURE_NAMES[:12]].describe().round(2).to_string())
