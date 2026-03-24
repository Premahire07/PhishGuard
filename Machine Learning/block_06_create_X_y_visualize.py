# ============================================================
# BLOCK 6 — Create Feature Matrix (X) and Label Vector (y)
#           + Data Visualization (7 charts)
# ============================================================

# ── X and y ───────────────────────────────────────────────────────
X = features_df.values        # shape: (n_samples, 25)
y = df["label"].values         # 0 = legitimate,  1 = phishing

print(f"X shape : {X.shape}   (samples × features)")
print(f"y shape : {y.shape}")
print()
print(f"Class distribution:")
print(f"  Legitimate (0) : {(y==0).sum():,}  ({(y==0).mean()*100:.1f}%)")
print(f"  Phishing   (1) : {(y==1).sum():,}  ({(y==1).mean()*100:.1f}%)")

mask_legit = y == 0
mask_phish = y == 1


# ── CHART 1: Class Distribution ───────────────────────────────────
counts     = pd.Series(y).value_counts().sort_index()
labels_txt = ["Legitimate", "Phishing"]
colors     = ["#22c55e", "#ef4444"]

fig, axes = plt.subplots(1, 2, figsize=(12, 4))
axes[0].bar(labels_txt, counts.values, color=colors, width=0.5, edgecolor="white")
for i, v in enumerate(counts.values):
    axes[0].text(i, v + 200, f"{v:,}", ha="center", fontweight="bold", fontsize=12)
axes[0].set_title("Class Distribution (Bar)", fontsize=13, fontweight="bold")
axes[0].set_ylabel("Count")
axes[0].grid(axis="y", alpha=0.3)

axes[1].pie(
    counts.values, labels=labels_txt, colors=colors,
    autopct="%1.1f%%", startangle=90,
    wedgeprops={"edgecolor": "white", "linewidth": 2},
    textprops={"fontsize": 12},
)
axes[1].set_title("Class Distribution (Pie)", fontsize=13, fontweight="bold")
plt.suptitle("Label Distribution in Dataset", fontsize=14, fontweight="bold")
plt.tight_layout()
plt.savefig("chart_01_class_distribution.png", dpi=120, bbox_inches="tight")
plt.show()
print("Saved → chart_01_class_distribution.png")


# ── CHART 2: Feature Distributions ───────────────────────────────
viz_feats = [
    "url_length", "dot_count", "path_length", "query_length",
    "domain_length", "domain_entropy", "longest_label_len", "digit_count",
]
fig, axes = plt.subplots(2, 4, figsize=(18, 8))
axes = axes.flatten()
for i, feat in enumerate(viz_feats):
    ax  = axes[i]
    idx = FEATURE_NAMES.index(feat)
    cap = np.percentile(X[:, idx], 99)
    ax.hist(np.clip(X[mask_legit, idx], 0, cap), bins=40, alpha=0.65,
            color="#22c55e", density=True, label="Legitimate")
    ax.hist(np.clip(X[mask_phish, idx], 0, cap), bins=40, alpha=0.65,
            color="#ef4444", density=True, label="Phishing")
    ax.axvline(X[mask_legit, idx].mean(), color="#22c55e", ls="--", lw=1.5)
    ax.axvline(X[mask_phish, idx].mean(), color="#ef4444", ls="--", lw=1.5)
    ax.set_title(feat.replace("_", " ").title(), fontsize=10, fontweight="bold")
    ax.set_ylabel("Density", fontsize=8)
    ax.grid(alpha=0.25)
    if i == 0:
        ax.legend(fontsize=8)
plt.suptitle("Feature Distributions: Phishing vs Legitimate", fontsize=14, fontweight="bold")
plt.tight_layout()
plt.savefig("chart_02_feature_distributions.png", dpi=120, bbox_inches="tight")
plt.show()
print("Saved → chart_02_feature_distributions.png")


# ── CHART 3: Correlation Heatmap ─────────────────────────────────
corr_df       = pd.DataFrame(X, columns=FEATURE_NAMES)
corr_df["label"] = y
corr          = corr_df.corr()
mask_upper    = np.triu(np.ones_like(corr, dtype=bool), k=1)

fig, ax = plt.subplots(figsize=(16, 13))
sns.heatmap(
    corr, mask=mask_upper,
    cmap=sns.diverging_palette(220, 20, as_cmap=True),
    center=0, annot=True, fmt=".2f",
    annot_kws={"size": 7}, square=True,
    linewidths=0.3, cbar_kws={"shrink": 0.7}, ax=ax,
)
ax.set_title("Feature Correlation Matrix", fontsize=14, fontweight="bold", pad=10)
plt.tight_layout()
plt.savefig("chart_03_correlation_heatmap.png", dpi=120, bbox_inches="tight")
plt.show()
print("Saved → chart_03_correlation_heatmap.png")

print("\nTop 10 features correlated with label (phishing=1):")
lc = corr["label"].drop("label").abs().sort_values(ascending=False)
for feat, val in lc.head(10).items():
    direction = "↑ phishing" if corr["label"][feat] > 0 else "↓ legit"
    print(f"  {feat:<28}  r={val:.4f}  {direction}")


# ── CHART 4: Binary Feature Comparison ───────────────────────────
binary_feats = [
    "has_at_symbol", "has_hyphen", "is_https", "has_ip_address",
    "free_tld", "suspicious_kw_in_domain", "brand_in_domain",
    "suspicious_kw_in_path", "is_random_domain", "both_gibberish",
]
legit_pct = [X[mask_legit, FEATURE_NAMES.index(f)].mean() * 100 for f in binary_feats]
phish_pct = [X[mask_phish, FEATURE_NAMES.index(f)].mean() * 100 for f in binary_feats]

x_pos = np.arange(len(binary_feats))
w     = 0.38
fig, ax = plt.subplots(figsize=(15, 6))
b1 = ax.bar(x_pos - w/2, legit_pct, w, label="Legitimate", color="#22c55e", alpha=0.85, edgecolor="white")
b2 = ax.bar(x_pos + w/2, phish_pct, w, label="Phishing",   color="#ef4444", alpha=0.85, edgecolor="white")
ax.set_xticks(x_pos)
ax.set_xticklabels([f.replace("_", "\n") for f in binary_feats], fontsize=9)
ax.set_ylabel("% of URLs with this feature")
ax.set_title("Binary Feature Prevalence: Phishing vs Legitimate", fontsize=13, fontweight="bold")
ax.legend(fontsize=11)
ax.grid(axis="y", alpha=0.3)
ax.set_ylim(0, 115)
for bar in list(b1) + list(b2):
    h = bar.get_height()
    if h > 4:
        ax.text(bar.get_x() + bar.get_width()/2, h + 1.5,
                f"{h:.0f}%", ha="center", va="bottom", fontsize=8, fontweight="bold")
plt.tight_layout()
plt.savefig("chart_04_binary_features.png", dpi=120, bbox_inches="tight")
plt.show()
print("Saved → chart_04_binary_features.png")


# ── CHART 5: Boxplots ────────────────────────────────────────────
box_feats = ["url_length", "domain_entropy", "longest_label_len",
             "query_length", "digit_count", "domain_length"]

fig, axes = plt.subplots(2, 3, figsize=(15, 8))
axes = axes.flatten()
for i, feat in enumerate(box_feats):
    ax  = axes[i]
    idx = FEATURE_NAMES.index(feat)
    cap = np.percentile(X[:, idx], 97)
    groups = [
        np.clip(X[mask_legit, idx], 0, cap),
        np.clip(X[mask_phish, idx], 0, cap),
    ]
    bp = ax.boxplot(groups, patch_artist=True, widths=0.5,
                    medianprops={"color": "white", "linewidth": 2})
    bp["boxes"][0].set_facecolor("#22c55e"); bp["boxes"][0].set_alpha(0.7)
    bp["boxes"][1].set_facecolor("#ef4444"); bp["boxes"][1].set_alpha(0.7)
    ax.set_xticks([1, 2])
    ax.set_xticklabels(["Legitimate", "Phishing"])
    ax.set_title(feat.replace("_", " ").title(), fontsize=11, fontweight="bold")
    ax.grid(axis="y", alpha=0.3)
plt.suptitle("Feature Boxplots by Class", fontsize=14, fontweight="bold")
plt.tight_layout()
plt.savefig("chart_05_boxplots.png", dpi=120, bbox_inches="tight")
plt.show()
print("Saved → chart_05_boxplots.png")


# ── CHART 6: Scatter — URL Length vs Domain Entropy ──────────────
idx_s = np.random.choice(len(X), size=min(6000, len(X)), replace=False)
X_s   = X[idx_s]
y_s   = y[idx_s]

fig, ax = plt.subplots(figsize=(11, 6))
for lval, col, lbl, mk in [
    (0, "#22c55e", "Legitimate", "o"),
    (1, "#ef4444", "Phishing",   "^"),
]:
    mask = y_s == lval
    ax.scatter(
        X_s[mask, FEATURE_NAMES.index("url_length")],
        X_s[mask, FEATURE_NAMES.index("domain_entropy")],
        c=col, alpha=0.35, s=18, marker=mk,
        label=f"{lbl} ({mask.sum():,})", edgecolors="none",
    )
ax.set_xlabel("URL Length", fontsize=12)
ax.set_ylabel("Domain Entropy  (high = random/gibberish)", fontsize=12)
ax.set_title("URL Length vs Domain Entropy", fontsize=13, fontweight="bold")
ax.legend(fontsize=11)
ax.grid(alpha=0.2)
plt.tight_layout()
plt.savefig("chart_06_scatter.png", dpi=120, bbox_inches="tight")
plt.show()
print("Saved → chart_06_scatter.png")


# ── CHART 7: HTTPS Usage by Class ────────────────────────────────
https_legit = X[mask_legit, FEATURE_NAMES.index("is_https")].mean() * 100
https_phish = X[mask_phish, FEATURE_NAMES.index("is_https")].mean() * 100

fig, ax = plt.subplots(figsize=(7, 5))
bars = ax.bar(["Legitimate", "Phishing"], [https_legit, https_phish],
              color=["#22c55e", "#ef4444"], width=0.4, edgecolor="white")
for bar, val in zip(bars, [https_legit, https_phish]):
    ax.text(bar.get_x() + bar.get_width()/2, val + 1,
            f"{val:.1f}%", ha="center", fontweight="bold", fontsize=13)
ax.set_ylabel("% of URLs using HTTPS")
ax.set_title("HTTPS Usage by Class\n(Phishers increasingly use HTTPS to appear legit)",
             fontsize=12, fontweight="bold")
ax.set_ylim(0, 110)
ax.grid(axis="y", alpha=0.3)
plt.tight_layout()
plt.savefig("chart_07_https_usage.png", dpi=120, bbox_inches="tight")
plt.show()
print("Saved → chart_07_https_usage.png")
