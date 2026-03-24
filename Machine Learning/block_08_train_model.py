# ============================================================
# BLOCK 8 — Select ML Algorithm & Train the Model
#           Algorithm: Random Forest Classifier
# ============================================================
#
# Why Random Forest?
#   ✅ Handles mixed feature types (binary flags + continuous values)
#   ✅ Robust to outliers in URL features
#   ✅ No feature scaling needed
#   ✅ Provides feature importance rankings
#   ✅ Fast prediction (~1ms per URL) — ideal for real-time use
#   ✅ class_weight='balanced' handles class imbalance automatically
# ============================================================

clf = RandomForestClassifier(
    n_estimators=400,         # number of decision trees in the forest
    max_depth=30,             # maximum depth of each tree
    min_samples_split=2,      # minimum samples required to split a node
    min_samples_leaf=1,       # minimum samples required in a leaf node
    class_weight="balanced",  # auto-weight classes to handle imbalance
    random_state=42,
    n_jobs=-1,                # use all available CPU cores
)

print("=== Random Forest Training ===")
print(f"  Trees      : {clf.n_estimators}")
print(f"  Max depth  : {clf.max_depth}")
print(f"  Train size : {len(X_train):,} samples")
print(f"  Features   : {X_train.shape[1]}")
print()
print("Training ...")

t0      = time.time()
clf.fit(X_train, y_train)
elapsed = time.time() - t0

print(f"✅ Training complete in {elapsed:.1f}s")
