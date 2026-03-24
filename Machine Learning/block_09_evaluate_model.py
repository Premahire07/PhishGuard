# ============================================================
# BLOCK 9 — Evaluate the Model
#           (accuracy, precision, recall, F1, AUC + 4 charts)
# ============================================================

THRESHOLD = 0.40   # classify as phishing if confidence >= 40%

y_proba = clf.predict_proba(X_test)[:, 1]   # probability of phishing
y_pred  = (y_proba >= THRESHOLD).astype(int)

# ── Metrics ───────────────────────────────────────────────────────
acc  = accuracy_score(y_test,  y_pred)
prec = precision_score(y_test, y_pred)
rec  = recall_score(y_test,    y_pred)
f1   = f1_score(y_test,        y_pred)
auc  = roc_auc_score(y_test,   y_proba)
cm   = confusion_matrix(y_test, y_pred)

print(f"""
╔══════════════════════════════════════════════════════════╗
║              MODEL EVALUATION RESULTS                    ║
╠══════════════════════════════════════════════════════════╣
║  Accuracy   : {acc*100:>8.3f}%                               ║
║  Precision  : {prec*100:>8.3f}%                               ║
║  Recall     : {rec*100:>8.3f}%                               ║
║  F1 Score   : {f1*100:>8.3f}%                               ║
║  ROC-AUC    : {auc:>8.4f}                                ║
╠══════════════════════════════════════════════════════════╣
║  Confusion Matrix:                                       ║
║    True  Neg (legit→legit)       : {cm[0][0]:>6,}           ║
║    False Pos (legit→phishing)    : {cm[0][1]:>6,}           ║
║    False Neg (phishing→legit)    : {cm[1][0]:>6,}           ║
║    True  Pos (phishing→phishing) : {cm[1][1]:>6,}           ║
╚══════════════════════════════════════════════════════════╝
""")

print("Detailed Classification Report:")
print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))


# ── CHART 9: Confusion Matrix ─────────────────────────────────────
fig, ax = plt.subplots(figsize=(7, 6))
sns.heatmap(
    cm, annot=True, fmt=",d", cmap="Blues",
    xticklabels=["Legitimate", "Phishing"],
    yticklabels=["Legitimate", "Phishing"],
    linewidths=2, annot_kws={"size": 16, "weight": "bold"},
    ax=ax, cbar=False,
)
ax.set_xlabel("Predicted Label", fontsize=12)
ax.set_ylabel("True Label", fontsize=12)
ax.set_title(f"Confusion Matrix  (Accuracy: {acc*100:.3f}%)", fontsize=13, fontweight="bold")
plt.tight_layout()
plt.savefig("chart_09_confusion_matrix.png", dpi=120, bbox_inches="tight")
plt.show()
print("Saved → chart_09_confusion_matrix.png")


# ── CHART 10: ROC Curve + Precision-Recall Curve ─────────────────
fpr, tpr, _      = roc_curve(y_test, y_proba)
prec_c, rec_c, _ = precision_recall_curve(y_test, y_proba)
ap               = average_precision_score(y_test, y_proba)

fig, axes = plt.subplots(1, 2, figsize=(14, 6))

ax = axes[0]
ax.plot(fpr, tpr, color="#6366f1", lw=2.5, label=f"AUC = {auc:.4f}")
ax.fill_between(fpr, tpr, alpha=0.1, color="#6366f1")
ax.plot([0, 1], [0, 1], "k--", lw=1, alpha=0.5, label="Random Classifier")
ax.set_xlabel("False Positive Rate", fontsize=11)
ax.set_ylabel("True Positive Rate", fontsize=11)
ax.set_title("ROC Curve", fontsize=13, fontweight="bold")
ax.legend(fontsize=11)
ax.grid(alpha=0.3)

ax2 = axes[1]
ax2.plot(rec_c, prec_c, color="#22c55e", lw=2.5, label=f"Avg Precision = {ap:.4f}")
ax2.fill_between(rec_c, prec_c, alpha=0.1, color="#22c55e")
ax2.set_xlabel("Recall", fontsize=11)
ax2.set_ylabel("Precision", fontsize=11)
ax2.set_title("Precision-Recall Curve", fontsize=13, fontweight="bold")
ax2.legend(fontsize=11)
ax2.grid(alpha=0.3)

plt.suptitle("Model Performance Curves", fontsize=14, fontweight="bold")
plt.tight_layout()
plt.savefig("chart_10_roc_pr_curves.png", dpi=120, bbox_inches="tight")
plt.show()
print("Saved → chart_10_roc_pr_curves.png")


# ── CHART 11: Feature Importances ────────────────────────────────
importances = pd.Series(clf.feature_importances_, index=FEATURE_NAMES).sort_values()

group_colors = (
    {f: "#6366f1" for f in FEATURE_NAMES[:12]}   |  # Structural - indigo
    {f: "#f59e0b" for f in FEATURE_NAMES[12:20]} |  # Semantic   - amber
    {f: "#22c55e" for f in FEATURE_NAMES[20:22]} |  # Entropy    - green
    {f: "#ef4444" for f in FEATURE_NAMES[22:]}      # DGA        - red
)
bar_colors = [group_colors[f] for f in importances.index]

fig, ax = plt.subplots(figsize=(11, 10))
bars = ax.barh(importances.index, importances.values,
               color=bar_colors, edgecolor="white", linewidth=0.4)
for bar, val in zip(bars, importances.values):
    ax.text(val + 0.001, bar.get_y() + bar.get_height()/2,
            f"{val*100:.2f}%", va="center", fontsize=8.5)
ax.set_xlabel("Importance Score", fontsize=11)
ax.set_title(f"Feature Importances — Random Forest ({clf.n_estimators} trees)",
             fontsize=13, fontweight="bold")
ax.grid(axis="x", alpha=0.25)

legend_elements = [
    mpatches.Patch(color="#6366f1", label="Structural (1–12)"),
    mpatches.Patch(color="#f59e0b", label="Semantic (13–20)"),
    mpatches.Patch(color="#22c55e", label="Entropy (21–22)"),
    mpatches.Patch(color="#ef4444", label="DGA (23–25)"),
]
ax.legend(handles=legend_elements, loc="lower right", fontsize=10)
plt.tight_layout()
plt.savefig("chart_11_feature_importance.png", dpi=120, bbox_inches="tight")
plt.show()
print("Saved → chart_11_feature_importance.png")

print("\nTop 10 most important features:")
for feat, imp in importances.sort_values(ascending=False).head(10).items():
    print(f"  {feat:<28}  {imp*100:.3f}%")


# ── CHART 12: Cross-Validation ────────────────────────────────────
print("\nRunning 5-fold cross-validation ...")
cv_scores = cross_val_score(clf, X, y, cv=5, scoring="roc_auc", n_jobs=-1)
print(f"  AUC per fold : {cv_scores}")
print(f"  Mean AUC     : {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

fig, ax = plt.subplots(figsize=(8, 5))
folds = [f"Fold {i+1}" for i in range(len(cv_scores))]
bars  = ax.bar(folds, cv_scores, color="#6366f1", width=0.5, edgecolor="white")
ax.axhline(cv_scores.mean(), color="#f59e0b", ls="--", lw=2,
           label=f"Mean AUC = {cv_scores.mean():.4f}")
ax.fill_between(range(len(cv_scores)),
                cv_scores.mean() - cv_scores.std(),
                cv_scores.mean() + cv_scores.std(),
                alpha=0.15, color="#f59e0b",
                label=f"±1 Std ({cv_scores.std():.4f})")
for bar, val in zip(bars, cv_scores):
    ax.text(bar.get_x() + bar.get_width()/2, val + 0.001,
            f"{val:.4f}", ha="center", fontweight="bold", fontsize=10)
ax.set_ylim(0.95, 1.005)
ax.set_ylabel("ROC-AUC Score")
ax.set_title("5-Fold Cross-Validation AUC", fontsize=13, fontweight="bold")
ax.legend(fontsize=10)
ax.grid(axis="y", alpha=0.3)
plt.tight_layout()
plt.savefig("chart_12_cross_validation.png", dpi=120, bbox_inches="tight")
plt.show()
print("Saved → chart_12_cross_validation.png")


# ── Real-world manual tests ───────────────────────────────────────
print()
print("=== Real-World URL Test Cases ===")
test_cases = [
    ("https://deficryptowallets.com/",                              1, "Crypto drainer"),
    ("https://ourlzllc.com/",                                       1, "Fake crypto exchange"),
    ("https://servcaccntwebappaoiuhyswerdg.dtuiertgdfhfgdj.com/?yyy", 1, "DGA double-gibberish"),
    ("https://paypal-secure.verify-account.xyz/login.php",          1, "PayPal brand spoof"),
    ("http://192.168.1.1/login.php",                                1, "IP as hostname"),
    ("http://paypal.com@phish.xyz/login",                           1, "@ redirect trick"),
    ("https://www.udemy.com/?utm_source=adwords&utm_campaign=India",0, "Udemy (long UTM)"),
    ("https://google.com/search?q=crypto",                          0, "Google search"),
    ("https://coinbase.com/dashboard",                              0, "Real Coinbase"),
    ("https://paypal.com/signin?utm_source=brand",                  0, "Real PayPal"),
    ("https://github.com/login",                                    0, "GitHub login"),
]

print(f"\n{'URL':<55} {'Expect':>8} {'Predict':>8} {'Conf':>7}  {'Pass':>4}")
print("-" * 90)
all_pass = True
for url, expected, label in test_cases:
    feats    = extract_features(url)
    prob     = clf.predict_proba([feats])[0][1]
    pred     = 1 if prob >= THRESHOLD else 0
    ok       = "✅" if pred == expected else "❌"
    if pred != expected:
        all_pass = False
    exp_txt  = "PHISH" if expected == 1 else "SAFE"
    pred_txt = "PHISH" if pred == 1 else "SAFE"
    print(f"{url[:54]:<55} {exp_txt:>8} {pred_txt:>8} {prob*100:>6.1f}%  {ok}")

print()
print(f"Result: {'🎉 ALL TESTS PASSED' if all_pass else '⚠️  Some tests failed'}")
