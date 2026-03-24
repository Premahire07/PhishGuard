# ============================================================
# BLOCK 10 — Save the Trained Model as a .pkl File
# ============================================================

import os

MODEL_PATH = "phishing.pkl"

# ── Save ──────────────────────────────────────────────────────────
with open(MODEL_PATH, "wb") as f:
    pickle.dump(clf, f)

size_mb = os.path.getsize(MODEL_PATH) / 1e6
print(f"✅ Model saved → {MODEL_PATH}  ({size_mb:.1f} MB)")
print()

# ── Verify: reload and predict ────────────────────────────────────
print("Verification — loading model back from disk ...")
with open(MODEL_PATH, "rb") as f:
    loaded_model = pickle.load(f)

test_url = "https://paypal-verify.xyz/login.php"
feats    = extract_features(test_url)
prob     = loaded_model.predict_proba([feats])[0][1]
pred     = "PHISHING ⚠️" if prob >= THRESHOLD else "SAFE ✅"
print(f"  URL        : {test_url}")
print(f"  Prediction : {pred}  ({prob*100:.1f}% phishing confidence)")
print()

# ── Final summary chart ───────────────────────────────────────────
metrics_names  = ["Accuracy", "Precision", "Recall", "F1 Score", "ROC-AUC"]
metrics_values = [acc, prec, rec, f1, auc]
colors_m       = ["#6366f1", "#22c55e", "#f59e0b", "#06b6d4", "#ef4444"]

fig, ax = plt.subplots(figsize=(10, 5))
bars = ax.bar(metrics_names, [v * 100 for v in metrics_values],
              color=colors_m, width=0.5, edgecolor="white")
for bar, val in zip(bars, metrics_values):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.3,
            f"{val*100:.3f}%", ha="center", fontweight="bold", fontsize=12)
ax.set_ylim(0, 110)
ax.set_ylabel("Score (%)", fontsize=12)
ax.set_title("PhishGuard — Final Model Performance Summary", fontsize=14, fontweight="bold")
ax.grid(axis="y", alpha=0.3)
ax.axhline(99, color="gray", ls="--", lw=1, alpha=0.5, label="99% reference")
ax.legend(fontsize=10)
plt.tight_layout()
plt.savefig("chart_13_final_summary.png", dpi=120, bbox_inches="tight")
plt.show()
print("Saved → chart_13_final_summary.png")

print()
print("=" * 55)
print("  PIPELINE COMPLETE")
print("=" * 55)
print(f"  Model file   : {MODEL_PATH}  ({size_mb:.1f} MB)")
print(f"  Algorithm    : Random Forest ({clf.n_estimators} trees)")
print(f"  Features     : {clf.n_features_in_}")
print(f"  Accuracy     : {acc*100:.3f}%")
print(f"  Precision    : {prec*100:.3f}%")
print(f"  Recall       : {rec*100:.3f}%")
print(f"  F1 Score     : {f1*100:.3f}%")
print(f"  ROC-AUC      : {auc:.4f}")
print()
print("  To use model in your app:")
print("    import pickle")
print("    with open('phishing.pkl', 'rb') as f:")
print("        model = pickle.load(f)")
print("    features = extract_features(url)")
print("    prob = model.predict_proba([features])[0][1]")
print("    prediction = 'PHISHING' if prob >= 0.40 else 'SAFE'")
