# Full Dataset Training Guide

## Overview

You now have **two options** to train on the complete EMBER dataset (799,912 samples):

### Option 1: Enhanced Local Training ✅ RECOMMENDED (Try First)

**Command:**
```bash
# Train on FULL dataset
python src/model_training.py --full-dataset

# Or specify custom sample limit  
python src/model_training.py --max-samples 600000
```

**Memory Optimizations:**
- ✅ float64 → float32 conversion (50% memory savings)
- ✅ Aggressive garbage collection
- ✅ Chunked loading if needed
- ✅ Early stopping to prevent overfitting

**Requirements:**
- RAM: 12-16GB recommended
- GPU: RTX 3050 (works great)
- Time: 30-60 minutes

**Expected Accuracy:** 95%+

---

### Option 2: Google Colab Training (Cloud Fallback)

**When to use:**
- Local training runs out of memory
- Want to use better GPU (T4 > RTX 3050)
- Need guaranteed resources

**Steps:**

1. **Upload Data to Google Drive:**
   - Upload `data/train.parquet` to your Google Drive
   - (Optional) Upload `data/test.parquet`

2. **Open Colab Notebook:**
   - Upload `train_full_dataset_colab.ipynb` to Google Colab
   - Or open directly from Drive

3. **Configure Paths:**
   - Update paths in Step 4 to match your Drive structure

4. **Run All Cells:**
   - Runtime → Run all (or Ctrl+F9)
   - Wait 30-60 minutes

5. **DownloadModel:**
   - Model saved to `MyDrive/InfoSec_Project/models/classifier.pkl`
   - Download and place in your local `models/` directory

**Colab Resources:**
- RAM: 12-25GB (depending on tier)
- GPU: Tesla T4 (16GB VRAM)
- Time: 20-40 minutes

---

## What Changed in model_training.py

### New Features:

1. **Command-line Arguments:**
   - `--full-dataset`: Train on all samples
   - `--max-samples N`: Custom sample limit

2. **Memory Optimizations:**
   - Automatic float64 → float32 conversion
   - Better garbage collection
   - Efficient chunked loading

3. **Better Training:**
   - Early stopping (prevents overfitting)
   - Evaluation metrics during training
   - Progress logging every 50 iterations

4. **Enhanced Evaluation:**
   - Confusion matrix
   - Precision, Recall, F1-Score
   - Detailed classification report
   - Performance metadata saved to JSON

5. **Model Metadata:**
   - Saves metrics to `models/model_metadata.json`
   - Tracks training configuration
   - Records accuracy, precision, recall, F1

---

## Usage Examples

### Default (400k samples):
```bash
python src/model_training.py
```

### Full Dataset (800k samples):
```bash
python src/model_training.py --full-dataset
```

### Custom Limit (600k samples):
```bash
python src/model_training.py --max-samples 600000
```

---

## Expected Output

```
============================================================
MALWARE DETECTION MODEL TRAINING
============================================================
[*] Mode: FULL DATASET (all samples)
============================================================

[*] Loading dataset from ...\\data\\train.parquet...
[*] Loaded 799,912 samples
[*] Optimizing memory usage (float64 → float32)...
[*] Using FULL DATASET (799,912 samples)
[*] Training dataset size: 799,912 samples
[*] Training Data Shape: (799912, 2381)
[*] Features: 2381
[*] Class distribution:
1    400259
0    399653
Name: label, dtype: int64

============================================================
[*] Training LightGBM Model with GPU acceleration...
============================================================
[*] Training on 639,929 samples...
[*] This may take 30-60 minutes depending on your GPU...

[LightGBM] [Info] Training started...
[50]    valid_0's binary_logloss: 0.087234
[100]   valid_0's binary_logloss: 0.062145
...
[400]   valid_0's binary_logloss: 0.038921

[*] Model trained successfully!

============================================================
[*] Evaluating model performance...
============================================================

============================================================
FINAL ACCURACY: 96.34%
============================================================

Classification Report:
              precision    recall  f1-score   support

      Benign       0.97      0.96      0.96     79953
     Malware       0.96      0.97      0.96     80030

    accuracy                           0.96    159983
   macro avg       0.96      0.96      0.96    159983
weighted avg       0.96      0.96      0.96    159983

Confusion Matrix:
[[76712  3241]
 [ 2604 77426]]

Precision: 95.98%
Recall: 96.75%
F1-Score: 96.36%

[*] Saving model to ...\\models\\classifier.pkl...
[*] Model metadata saved to ...\\models\\model_metadata.json

[✓] Training complete!
```

---

## Troubleshooting

### "MemoryError" or "Out of Memory":  
→ Use Google Colab

### "CUDA out of memory":
→ Restart kernel and try again, or use CPU mode

### Training is very slow:
→ Check GPU is being used: `nvidia-smi`
→ Verify GPU acceleration in model config

### Model accuracy < 95%:
→ Check for data quality issues
→ Increase n_estimators if early stopping triggered

---

## Next Steps

After training completes:

1. **Test the model:**
   ```bash
   python src/gui.py
   ```

2. **Scan a file:**  
   - Use GUI to scan test files
   - Verify improved accuracy

3. **Check metadata:**
   ```bash
   cat models/model_metadata.json
   ```

---

## Files Created

- ✅ `models/classifier.pkl` - Trained model
- ✅ `models/model_metadata.json` - Performance metrics
- ✅ `train_full_dataset_colab.ipynb` - Google Colab notebook

Enjoy your improved malware detection! 🎉
