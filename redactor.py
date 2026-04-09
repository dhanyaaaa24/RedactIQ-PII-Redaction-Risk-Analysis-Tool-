import re

class Redactor:
    def __init__(self):
        self.patterns = {
            'EMAIL': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'PHONE': r'\b\d{10}\b|\(\d{3}\)\s?\d{3}-\d{4}',
            'CREDIT_CARD': r'\b(?:\d[ -]*?){13,16}\b',
            'IPV4': r'\b\d{1,3}(?:\.\d{1,3}){3}\b'
        }

    def mask_email(self, email):
        parts = email.split('@')
        name = parts[0]
        domain = parts[1]
        return name[0] + "*****@" + domain

    def mask_phone(self, phone):
        return "******" + phone[-4:]

    def mask_card(self, card):
        digits = re.sub(r'\D', '', card)
        return "*" * (len(digits) - 4) + digits[-4:]

    def mask_ip(self, ip):
        parts = ip.split('.')
        return f"{parts[0]}.{parts[1]}.*.*"

    def redact(self, text):
        redacted_text = text
        counts = {key: 0 for key in self.patterns.keys()}

        # EMAIL
        emails = re.findall(self.patterns['EMAIL'], redacted_text)
        for email in emails:
            redacted_text = redacted_text.replace(email, self.mask_email(email))
        counts['EMAIL'] = len(emails)

        # PHONE
        phones = re.findall(self.patterns['PHONE'], redacted_text)
        for phone in phones:
            redacted_text = redacted_text.replace(phone, self.mask_phone(phone))
        counts['PHONE'] = len(phones)

        # CREDIT CARD
        cards = re.findall(self.patterns['CREDIT_CARD'], redacted_text)
        for card in cards:
            redacted_text = redacted_text.replace(card, self.mask_card(card))
        counts['CREDIT_CARD'] = len(cards)

        # IPV4
        ips = re.findall(self.patterns['IPV4'], redacted_text)
        for ip in ips:
            redacted_text = redacted_text.replace(ip, self.mask_ip(ip))
        counts['IPV4'] = len(ips)

        return redacted_text, counts