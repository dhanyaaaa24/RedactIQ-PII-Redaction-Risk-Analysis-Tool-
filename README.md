# 🔐 RedactIQ – PII Redaction & Risk Analysis Tool

## 📌 Overview
RedactIQ is a Python-based utility that detects and redacts sensitive data (Personally Identifiable Information - PII) such as emails, phone numbers, credit card details, and IP addresses from log files. It also analyzes the data to calculate a risk score and identify suspicious activity patterns.

---

## 🚀 Features
- Detects sensitive data:
  - Emails  
  - Phone numbers  
  - Credit card numbers  
  - IP addresses  
- Redacts PII using Regular Expressions (Regex)  
- Calculates risk score using weighted logic  
- Classifies logs into Low, Medium, and High risk levels  
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
'''
RedactIQ/
│
├── main.py
├── redactor.py
├── risk_iq.py
├── sample.log
├── redacted.log
└── risk_report.csv
'''
---

## ▶️ How to Run
python3 main.py

---

## 📊 Output
- redacted.log → cleaned log file with sensitive data masked  
- risk_report.csv → structured report containing:
  - Detected PII counts  
  - Total risk score  
  - Final risk level  
  - Most frequent IP  

---

## 🎯 Use Case
This project simulates real-world log monitoring systems used in cybersecurity to:
- Detect sensitive data exposure  
- Prevent data leaks  
- Identify suspicious activity patterns  
- Assist in security analysis and compliance  

---

## 🧠 How It Works
1. Reads log file line-by-line  
2. Detects PII using Regex patterns  
3. Replaces sensitive data with labels like [EMAIL], [PHONE]  
4. Counts occurrences of each data type  
5. Calculates risk score using weighted logic  
6. Tracks repeated IP activity  
7. Generates a CSV report for analysis  

---

## 🔮 Future Improvements
- Real-time log monitoring  
- Dashboard visualization  
- AI/ML-based anomaly detection  
- Integration with security tools  
