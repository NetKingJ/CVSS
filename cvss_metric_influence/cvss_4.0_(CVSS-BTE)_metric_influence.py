"""
Compute the average influence of every CVSS‑v4.0 metric—including
supplemental, environmental, and threat metrics—on the Base score.
Runs combinations in parallel and prints a descending influence list.
"""
from itertools import product
from multiprocessing import Pool
from cvss import CVSS4

# CVSS 4.0 metric value sets (CVSS-BTE)
METRICS = {
    "AV": ["N", "A", "L", "P"],
    "AC": ["L", "H"],
    "AT": ["N", "P"],
    "PR": ["N", "L", "H"],
    "UI": ["N", "P", "A"],
    "VC": ["H", "L", "N"],
    "VI": ["H", "L", "N"],
    "VA": ["H", "L", "N"],
    "SC": ["H", "L", "N"],
    "SI": ["H", "L", "N"],
    "SA": ["H", "L", "N"],
    "S":  ["X", "N", "P"],
    "AU": ["X", "N", "Y"],
    "R":  ["X", "A", "U", "I"],
    "V":  ["X", "D", "C"],
    "RE": ["X", "L", "M", "H"],
    "U":  ["X", "Clear", "Green", "Amber", "Red"],
    "E":  ["X", "A", "P", "U"],
}

ORDER = [
    "AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA",
    "S", "AU", "R", "V", "RE", "U", "E"
]


def metric_influence(target: str) -> tuple[str, float]:
    """Return (metric, average delta) produced by varying target."""
    others = {m: v for m, v in METRICS.items() if m != target}
    total, cases = 0.0, 0

    for combo in product(*others.values()):
        fixed = dict(zip(others.keys(), combo))
        scores = [
            CVSS4(
                "CVSS:4.0/" + "/".join(f"{m}:{(fixed | {target: val})[m]}" for m in ORDER)
            ).scores()[0]
            for val in METRICS[target]
        ]
        total += max(scores) - min(scores)
        cases += 1

    return target, (total / cases) if cases else 0.0


if __name__ == "__main__":
    with Pool() as pool:
        results = pool.map(metric_influence, METRICS.keys(), chunksize=1)
        
    for metric, influence in sorted(results, key=lambda x: x[1], reverse=True):
        print(f"{metric}: {influence}")
