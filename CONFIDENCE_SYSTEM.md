# 3-Tier Confidence System - Quick Reference

## Color-Coded Confidence Levels

### 🟢 GREEN - Benign (Safe)
- **Threshold**: 90%+ confidence
- **Meaning**: High certainty the file is legitimate and safe
- **Action**: File is safe to use
- **Example**: "Benign (95.2%)"

### 🟡 YELLOW - Suspicious (Uncertain)
- **Threshold**: Below 90% confidence
- **Meaning**: Medium/low confidence, needs review
- **Action**: Manual inspection recommended, quarantine if unsure
- **Examples**: 
  - "Suspicious (60%)" - Modified EICAR
  - "Suspicious (75%)" - Unknown file type
  - "Suspicious (85%)" - Borderline benign

### 🔴 RED - Malware (Dangerous)
- **Threshold**: 95%+ malware confidence
- **Meaning**: High certainty the file is malicious
- **Action**: Immediate quarantine recommended
- **Example**: "Malware (98.5%)"

## How It Works

1. **Ensemble Models**: 3 LightGBM models predict probabilities
2. **Probability Averaging**: Average predictions across models
3. **Calibration**: Boost confident predictions to 95%+
4. **Threshold Check**:
   - Malware 95%+ → RED
   - Benign 90%+ → GREEN
   - Everything else → YELLOW

## Examples

| File | Raw Confidence | Calibrated | Color | Status |
|------|---------------|------------|-------|--------|
| calc.exe | 88% benign | 95% | 🟢 GREEN | Benign |
| rufus.exe | 92% benign | 97% | 🟢 GREEN | Benign |
| modified_eicar.exe | 60% benign | 60% | 🟡 YELLOW | Suspicious |
| packed.exe | 75% benign | 85% | 🟡 YELLOW | Suspicious |
| virus.exe | 96% malware | 98% | 🔴 RED | Malware |
| trojan.exe | 88% malware | 95% | 🔴 RED | Malware |

## Key Points

- **Yellow = Caution**: Anything below 90% confidence is suspicious
- **Conservative**: Better to flag uncertain files than miss threats
- **User Control**: Quarantine button available for both red and yellow
- **Clear Visual**: Color-coded borders and text in GUI
