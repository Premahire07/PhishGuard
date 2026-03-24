PhishGuard — Machine Learning Pipeline
=======================================

BLOCKS (run in order)
----------------------
block_01_imports.py          → Install & import all libraries
block_02_load_dataset.py     → Load / generate dataset into pandas
block_03_clean_preprocess.py → Remove duplicates, missing values
block_04_feature_functions.py → Define 25 URL feature extractors
block_05_convert_features.py → Convert all URLs to numbers
block_06_create_X_y_visualize.py → Build X/y + 7 data visualizations
block_07_train_test_split.py → 80/20 stratified split
block_08_train_model.py      → Train Random Forest (400 trees)
block_09_evaluate_model.py   → Accuracy, precision, recall, AUC + 4 charts
block_10_save_model.py       → Save model as phishing.pkl

RUN ALL AT ONCE
---------------
  python run_all.py

RUN ONE BLOCK AT A TIME
-----------------------
  python block_01_imports.py
  python block_02_load_dataset.py
  ... etc.

REQUIREMENTS
------------
  pip install scikit-learn pandas numpy matplotlib seaborn

OUTPUT FILES
------------
  phishing.pkl                → trained model (copy to backend/)
  chart_01_class_distribution.png
  chart_02_feature_distributions.png
  chart_03_correlation_heatmap.png
  chart_04_binary_features.png
  chart_05_boxplots.png
  chart_06_scatter.png
  chart_07_https_usage.png
  chart_08_train_test_split.png
  chart_09_confusion_matrix.png
  chart_10_roc_pr_curves.png
  chart_11_feature_importance.png
  chart_12_cross_validation.png
  chart_13_final_summary.png

25 FEATURES (3 groups)
----------------------
  Structural (1-12)  : url_length, dot_count, has_at_symbol, has_hyphen,
                       subdomain_count, is_https, path_length, query_length,
                       has_ip_address, special_char_count, double_slash_count,
                       digit_count
  Semantic  (13-20)  : suspicious_kw_in_domain, brand_in_domain, free_tld,
                       domain_length, domain_digit_ratio, suspicious_kw_in_path,
                       hyphen_count_domain, brand_in_subdomain
  Entropy   (21-22)  : domain_entropy, is_random_domain
  DGA       (23-25)  : subdomain_is_gibberish, longest_label_len, both_gibberish

LOAD MODEL IN YOUR OWN CODE
-----------------------------
  import pickle
  from block_04_feature_functions import extract_features

  with open("phishing.pkl", "rb") as f:
      model = pickle.load(f)

  url      = "https://paypal-verify.xyz/login"
  features = extract_features(url)
  prob     = model.predict_proba([features])[0][1]
  result   = "PHISHING" if prob >= 0.40 else "SAFE"
  print(result)
