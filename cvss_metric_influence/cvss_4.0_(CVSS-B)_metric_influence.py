"""
Compute the average influence of each CVSS‑v4.0 metric on the Base score.
Runs every metric value against all combinations of the others, in parallel,
then prints a descending influence ranking.
"""
from itertools import product
from multiprocessing import Pool
from cvss import CVSS4

# Extended CVSS 4.0 metric value sets
METRICS = {
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
}

ORDER = ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA']


def metric_influence(target: str) -> tuple[str, float]:
    """Return (metric_name, average score delta) for *target* metric."""
    others = {m: v for m, v in METRICS.items() if m != target}
    total, cases = 0.0, 0

    for combo in product(*others.values()):
        fixed = dict(zip(others.keys(), combo))
        scores = []
        for val in METRICS[target]:
            current = fixed | {target: val}
            vector = "CVSS:4.0/" + "/".join(f"{m}:{current[m]}" for m in ORDER)
            scores.append(CVSS4(vector).scores()[0])
        total += max(scores) - min(scores)
        cases += 1

    return target, total / cases if cases else 0.0


if __name__ == "__main__":
    with Pool() as pool:
        results = pool.map(metric_influence, METRICS.keys(), chunksize=1)

    for m, influence in sorted(results, key=lambda x: x[1], reverse=True):
        print(f"{m}: {influence}")
