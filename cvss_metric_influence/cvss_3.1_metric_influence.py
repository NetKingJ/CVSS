from itertools import product
from cvss import CVSS3

# Define CVSS 3.1 metrics
metrics = {
    'AV': ['N', 'A', 'L', 'P'],
    'AC': ['L', 'H'],
    'PR': ['N', 'L', 'H'],
    'UI': ['N', 'R'],
    'S': ['U', 'C'],
    'C': ['H', 'L', 'N'],
    'I': ['H', 'L', 'N'],
    'A': ['H', 'L', 'N']
}

def metric_influence(metric_name):
    # Generate all combinations of metrics except the target one
    other_metrics = {m: v for m, v in metrics.items() if m != metric_name}
    all_combinations = product(*other_metrics.values())
    differences = []

    for comb in all_combinations:
        # Map current combination to a dictionary
        fixed = dict(zip(other_metrics.keys(), comb))

        scores = []
        for val in metrics[metric_name]:
            # Construct the CVSS vector string
            vector_parts = []
            # Ensure the order: AV,AC,PR,UI,S,C,I,A (S must follow UI)
            # Format: CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X
            vector_order = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']

            # Reconstruct vector based on the correct order
            vector_values = {}
            for m in vector_order:
                if m == metric_name:
                    vector_values[m] = val
                else:
                    vector_values[m] = fixed[m]

            vector_str = "CVSS:3.1/" + "/".join([f"{m}:{v}" for m, v in vector_values.items()])
            cvss = CVSS3(vector_str)
            score = cvss.scores()[0]
            scores.append(score)

        # Calculate the score difference caused by changing the target metric
        diff = max(scores) - min(scores)
        differences.append(diff)

    # Return average influence
    return sum(differences) / len(differences) if differences else 0

# Calculate influence for all metrics
influences = {}
for m in metrics:
    influences[m] = metric_influence(m)

# Sort by influence in descending order
sorted_by_influence = sorted(influences.items(), key=lambda x: x[1], reverse=True)

# Print results
print("CVSS 3.1 Metric Influence Ranking (Descending):")
for metric, inf in sorted_by_influence:
    print(f"{metric}: {inf}")
