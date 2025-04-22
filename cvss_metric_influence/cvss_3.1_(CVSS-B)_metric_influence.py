"""
Compute the mean influence of every CVSS‑v3.1 metric on the Base score.
Vary one metric while fixing all others, average the score deltas,
and output a descending influence ranking.
"""
from itertools import product
from cvss import CVSS3

# CVSS 3.1 metric value sets
METRICS = {
    "AV": ["N", "A", "L", "P"],
    "AC": ["L", "H"],
    "PR": ["N", "L", "H"],
    "UI": ["N", "R"],
    "S":  ["U", "C"],
    "C":  ["H", "L", "N"],
    "I":  ["H", "L", "N"],
    "A":  ["H", "L", "N"],
}

ORDER = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]


def metric_influence(target: str) -> float:
    """Return average score delta when *target* metric varies."""
    others = {m: v for m, v in METRICS.items() if m != target}
    deltas = []

    for combo in product(*others.values()):
        fixed = dict(zip(others.keys(), combo))
        scores = [
            CVSS3(
                "CVSS:3.1/"+ "/".join(
                    f"{m}:{(fixed | {target: val})[m]}"
                    for m in ORDER
                )
            ).scores()[0]
            for val in METRICS[target]
        ]
        deltas.append(max(scores) - min(scores))

    return sum(deltas) / len(deltas) if deltas else 0.0


if __name__ == "__main__":
    influences = {m: metric_influence(m) for m in METRICS}
    for metric, inf in sorted(influences.items(), key=lambda x: x[1], reverse=True):
        print(f"{metric}: {inf}")
