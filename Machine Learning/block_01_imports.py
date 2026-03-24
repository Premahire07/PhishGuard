# ============================================================
# BLOCK 1 — Install & Import Libraries
# ============================================================
# Run this first before any other block
#
# To install: pip install scikit-learn pandas numpy matplotlib seaborn

import re
import math
import pickle
import warnings
import time
from collections import Counter
from urllib.parse import urlparse

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
    roc_curve,
    precision_recall_curve,
    average_precision_score,
)

warnings.filterwarnings("ignore")
print("✅ All libraries imported successfully")
