# ============================================================
# BLOCK 7 — Split Dataset into Training and Testing Sets
#           (80% train, 20% test, stratified)
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.20,     # 20% held out for testing
    random_state=42,
    stratify=y,         # keep same class ratio in both splits
)

print("=== Train / Test Split ===")
print(f"Total samples : {len(X):,}")
print(f"Train         : {len(X_train):,}  ({len(X_train)/len(X)*100:.0f}%)")
print(f"Test          : {len(X_test):,}  ({len(X_test)/len(X)*100:.0f}%)")
print(f"Features      : {X_train.shape[1]}")
print()
print(f"Train — Legit: {(y_train==0).sum():,}  |  Phishing: {(y_train==1).sum():,}")
print(f"Test  — Legit: {(y_test==0).sum():,}   |  Phishing: {(y_test==1).sum():,}")
print()

# ── CHART: Train/Test split visualization ────────────────────────
categories = ["Train\n(Legitimate)", "Train\n(Phishing)", "Test\n(Legitimate)", "Test\n(Phishing)"]
values     = [(y_train==0).sum(), (y_train==1).sum(), (y_test==0).sum(), (y_test==1).sum()]
colors_bar = ["#16a34a", "#dc2626", "#4ade80", "#f87171"]

fig, ax = plt.subplots(figsize=(9, 4))
bars = ax.bar(categories, values, color=colors_bar, width=0.5, edgecolor="white")
for bar, val in zip(bars, values):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 100,
            f"{val:,}", ha="center", fontweight="bold", fontsize=11)
ax.set_title("Train / Test Split by Class", fontsize=13, fontweight="bold")
ax.set_ylabel("Number of Samples")
ax.grid(axis="y", alpha=0.3)
plt.tight_layout()
plt.savefig("chart_08_train_test_split.png", dpi=120, bbox_inches="tight")
plt.show()
print("Saved → chart_08_train_test_split.png")
