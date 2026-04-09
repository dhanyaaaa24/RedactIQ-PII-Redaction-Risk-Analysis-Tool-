class RiskEngine:
    def __init__(self):
        # Assign weights to different data types
        self.weights = {
            'EMAIL': 2,
            'PHONE': 3,
            'CREDIT_CARD': 5,
            'IPV4': 1
        }

    def calculate_score(self, counts):
        total_score = 0

        for label, count in counts.items():
            total_score += count * self.weights.get(label, 0)

        # Risk classification
        if total_score == 0:
            level = "NONE"
        elif total_score < 5:
            level = "LOW"
        elif total_score < 15:
            level = "MEDIUM"
        else:
            level = "HIGH"

        return total_score, level