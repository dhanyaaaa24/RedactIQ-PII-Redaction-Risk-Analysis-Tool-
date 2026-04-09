import csv
import re
from redactor import Redactor
from risk_iq import RiskEngine


def process_logs(log1, output_file, report_file):
    redactor = Redactor()
    risk_engine = RiskEngine()

    total_stats = {}
    ip_counts = {}

    with open(log1, 'r') as f, open(output_file, 'w') as out:
        lines = f.readlines()

        for line in lines:
            # Step 1: Redact PII
            clean_line, counts = redactor.redact(line)
            out.write(clean_line)

            # Step 2: Aggregate counts
            for label, count in counts.items():
                total_stats[label] = total_stats.get(label, 0) + count

            # Step 3: Track IP frequency
            ips = re.findall(r"\\b\\d{1,3}(?:\\.\\d{1,3}){3}\\b", line)
            for ip in ips:
                ip_counts[ip] = ip_counts.get(ip, 0) + 1

    # Step 4: Risk calculation
    score, level = risk_engine.calculate_score(total_stats)

    # Step 5: Find most frequent IP
    if ip_counts:
        suspicious_ip = max(ip_counts, key=ip_counts.get)
    else:
        suspicious_ip = "None"

    # Step 6: Generate CSV report
    with open(report_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        writer.writerow(['Metric', 'Value'])

        for label, count in total_stats.items():
            writer.writerow([f'Detected {label}s', count])

        writer.writerow(['Total Risk Score', score])
        writer.writerow(['Final Risk Level', level])
        writer.writerow(['Most Frequent IP', suspicious_ip])

    print(f"✅ Process Complete! Risk Level: {level}")
    print(f"🚨 Most Frequent IP: {suspicious_ip}")


# Run script
if __name__ == "__main__":
    # Create sample log
    with open("sample.log", "w") as f:
        f.write("User login failed for dhanya@gmail.com from IP 192.168.1.1\n")
        f.write("Payment using card 4111 1111 1111 1111 failed\n")
        f.write("Retry login from IP 192.168.1.1\n")
        f.write("Retry login from IP 192.168.1.1\n")
        f.write("Contact: 9876543210\n")

    process_logs("sample.log", "redacted.log", "risk_report.csv")