import math

def calculate_cvss_base_score(cvss_string):
    # Metric values based on CVSS 3.1 specification
    metric_values = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
        "AC": {"L": 0.77, "H": 0.44},
        "PR": {"N": 0.85, "L": [0.68, 0.62], "H": [0.5, 0.27]},  # [Scope changed, Scope unchanged]
        "UI": {"N": 0.85, "R": 0.62},
        "S": {"U": 6.42, "C": 7.52},
        "C": {"N": 0.0, "L": 0.22, "H": 0.56},
        "I": {"N": 0.0, "L": 0.22, "H": 0.56},
        "A": {"N": 0.0, "L": 0.22, "H": 0.56}
    }

    # Parse the CVSS vector string into a dictionary
    metrics = {m.split(':')[0]: m.split(':')[1] for m in cvss_string.split('/')[1:]}

    # Look up metric scores
    metric_scores = {k: metric_values[k][v] for k, v in metrics.items()}

    # Calculate Impact Sub-Score (ISS)
    ISS = 1 - (1 - metric_scores['C']) * (1 - metric_scores['I']) * (1 - metric_scores['A'])

    if metrics["S"] == "U":  # Unchanged Scope
        if metrics['PR'] == "N":
            Exploitability = 8.22 * metric_scores['AV'] * metric_scores['AC'] * metric_scores['PR'] * metric_scores['UI']
        else:
            Exploitability = 8.22 * metric_scores['AV'] * metric_scores['AC'] * metric_scores['PR'][1] * metric_scores['UI']
        Impact = 6.42 * ISS
        cvss_score = min(Exploitability + Impact, 10)
    else:  # Changed Scope
        if metrics['PR'] == "N":
            Exploitability = 8.22 * metric_scores['AV'] * metric_scores['AC'] * metric_scores['PR'] * metric_scores['UI']
        else:
            Exploitability = 8.22 * metric_scores['AV'] * metric_scores['AC'] * metric_scores['PR'][0] * metric_scores['UI']
        Impact = 7.52 * (ISS - 0.029) - 3.25 * ((ISS - 0.02) ** 15)
        cvss_score = 1.08 * (Exploitability + Impact)

    # Return 0 if Impact is zero or negative
    if Impact <= 0:
        return 0
    else:
        # Ensure score does not exceed 10 and round up to one decimal place
        if cvss_score > 10:
            return 10.0
        return math.ceil(cvss_score * 10) / 10

# Example usage
cvss_string = "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"
base_score = calculate_cvss_base_score(cvss_string)
print(base_score)
