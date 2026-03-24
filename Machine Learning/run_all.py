# ============================================================
# run_all.py — Run All 10 Blocks in Sequence
# ============================================================
# Usage:
#   python run_all.py
#
# Or run each block individually:
#   python block_01_imports.py
#   python block_02_load_dataset.py
#   ... and so on
# ============================================================

exec(open("block_01_imports.py").read())
exec(open("block_02_load_dataset.py").read())
exec(open("block_03_clean_preprocess.py").read())
exec(open("block_04_feature_functions.py").read())
exec(open("block_05_convert_features.py").read())
exec(open("block_06_create_X_y_visualize.py").read())
exec(open("block_07_train_test_split.py").read())
exec(open("block_08_train_model.py").read())
exec(open("block_09_evaluate_model.py").read())
exec(open("block_10_save_model.py").read())
