from itertools import product
from cvss import CVSS4
import multiprocessing

# CVSS 4.0 metric definitions (extended version)
metrics = {
    'AV': ['N', 'A', 'L', 'P'],
    'AC': ['L', 'H'],
    'AT': ['N', 'P'],
    'PR': ['N', 'L', 'H'],
    'UI': ['N', 'P', 'A'],
    'VC': ['H', 'L', 'N'],
    'VI': ['H', 'L', 'N'],
    'VA': ['H', 'L', 'N'],
    'SC': ['H', 'L', 'N'],
    'SI': ['H', 'L', 'N'],
    'SA': ['H', 'L', 'N'],
    'S': ['X', 'N', 'P'],
    'AU': ['X', 'N', 'Y'],
    'R': ['X', 'A', 'U', 'I'],
    'V': ['X', 'D', 'C'],
    'RE': ['X', 'L', 'M', 'H'],
    'U': ['X', 'Clear', 'Green', 'Amber', 'Red'],
    'E': ['X', 'A', 'P', 'U']
}

def metric_influence(metric_name):
    # Create all combinations of other metrics except the target metric
    other_metrics = {m: v for m, v in metrics.items() if m != metric_name}
    all_combinations = product(*other_metrics.values())
    metric_order = ['AV','AC','AT','PR','UI','VC','VI','VA','SC','SI','SA',
                    'S','AU','R','V','RE','U','E']

    sum_differences = 0.0
    count = 0
    
    for comb in all_combinations:
        fixed = dict(zip(other_metrics.keys(), comb))
        scores = []
        for val in metrics[metric_name]:
            current_set = fixed.copy()
            current_set[metric_name] = val
            
            vector_str = "CVSS:4.0/" + "/".join(f"{m}:{current_set[m]}" for m in metric_order)
            cvss = CVSS4(vector_str)
            score = cvss.scores()[0]
            scores.append(score)
        
        # Calculate the score difference caused by the metric's variation
        diff = max(scores) - min(scores)
        sum_differences += diff
        count += 1
    
    # Return average score influence for the given metric
    return (metric_name, sum_differences/count if count > 0 else 0.0)

if __name__ == "__main__":
    with multiprocessing.Pool() as pool:
        # Use small chunksize to reduce memory usage
        results = pool.map(metric_influence, metrics.keys(), chunksize=1)
    
    # Sort metrics by influence in descending order
    sorted_by_influence = sorted(results, key=lambda x: x[1], reverse=True)
    
    print("CVSS 4.0 (Extended Metrics) Influence Ranking (Descending):")
    for metric, inf in sorted_by_influence:
        print(f"{metric}: {inf}")
