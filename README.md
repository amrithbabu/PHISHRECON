# PhishRecon – ML-Based Phishing Detection Tool

## Overview
PhishRecon is a Python-based cybersecurity tool that uses machine learning and web security analysis to identify potentially malicious URLs and assess common web application security risks.

## Features
- **Machine Learning:** Random Forest-based URL classification.
- **URL Analysis:** Detects suspicious URL characteristics and patterns.
- **Risk Assessment:** Generates a risk score out of 100.
- **Header Analysis:** Checks important HTTP security headers.
- **Directory Scanning:** Checks selected common paths.
- **XSS Detection:** Tests for reflected cross-site scripting indicators.
- **SQL Injection Detection:** Checks for common SQL error indicators.
- **Image Analysis:** Inspects image file size, format, metadata, and suspicious embedded strings.
- **Batch Scanning:** Supports scanning URLs from a file.

## Technologies Used
- Python
- Scikit-learn
- Requests
- Pillow
- Colorama

## Installation
Clone the repository and enter the project directory:

```bash
git clone https://github.com/amrithbabu/PHISHRECON.git
cd phishrecon
```

Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Place the required trained model file, `model.pkl`, in the configured project location and ensure the code uses the correct paths.

## Usage

Quick URL scan:

```bash
phishrecon -u https://example.com --scan
```

Full scan:

```bash
phishrecon -u https://example.com --full
```

Scan URLs from a file:

```bash
phishrecon -f urls.txt --scan
```

Scan a local image:

```bash
phishrecon --image-file sample.jpg
```

Scan an image URL:

```bash
phishrecon --image-url "https://example.com/sample.jpg"
```

## Disclaimer
This project is intended for educational and authorized security testing only. Scan only websites and systems for which you have permission. Detection results are indicators, not proof that a vulnerability exists.
