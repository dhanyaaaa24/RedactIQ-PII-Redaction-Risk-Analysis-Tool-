# 🔐 RedactIQ – PII Redaction & Risk Analysis Tool

## 📌 Overview
RedactIQ is a Python-based utility that detects and redacts sensitive data (PII) such as emails, phone numbers, credit card details, and IP addresses from log files. It also analyzes the data to calculate a risk score and identify suspicious patterns.

---

## 🚀 Features
- Detects Emails, Phone Numbers, Credit Cards, IP Addresses
- Redacts sensitive data using Regex
- Calculates risk score using weighted logic
- Classifies logs into Low, Medium, High risk levels
- Identifies most frequent IP (potential suspicious activity)
- Generates structured CSV reports

---

## 🛠 Tech Stack
- Python
- Regular Expressions (Regex)
- File Handling
- CSV

---

## 📂 Project Structure
main.py
redactor.py
risk_iq.py
sample.log
redacted.log
risk_report.csv


---

## ▶️ How to Run
```bash
python3 main.py


📊 Output
	•	redacted.log → cleaned log file
	•	risk_report.csv → risk analysis report

