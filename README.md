# AI Antivirus Project

## Overview
This project is a Python-based AI Antivirus that uses Machine Learning to detect malware.

## Directory Structure
- **data/**: Contains raw malware samples and CSV datasets.
- **models/**: Stores trained model files (.pkl).
- **src/**: Source code for the application.
  - `feature_extraction.py`: Logic for extracting features from PE files.
  - `model_training.py`: Logic for training ML models.
  - `scanner_engine.py`: Core engine combining extraction and prediction.
  - `gui.py`: User interface.

## Setup
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Run the application:
   ```bash
   python src/gui.py
   ```
