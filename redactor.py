import re

class Redactor:
    def __init__(self):
        # Define regex patterns for different PII types
        self.patterns = {
            "EMAIL": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "PHONE": r"\b\d{10}\b|\(\d{3}\)\s\d{3}-\d{4}",
            "CREDIT_CARD": r"\b(?:\d[ -]*?){13,16}\b",
            "IPV4": r"\b\d{1,3}(?:\.\d{1,3}){3}\b"
        }

    def redact(self, text):
        redacted_text = text

        # Initialize count dictionary
        counts = {
            "EMAIL": 0,
            "PHONE": 0,
            "CREDIT_CARD": 0,
            "IPV4": 0
        }

        # Loop through each pattern
        for label, pattern in self.patterns.items():
            matches = re.findall(pattern, redacted_text)
            counts[label] = len(matches)

            # Replace matches with label
            redacted_text = re.sub(pattern, f"[{label}]", redacted_text)

        return redacted_text, counts