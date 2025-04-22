"""
Return the Base score for a given CVSS‑v3.1 vector.
Implements the official formula including Scope handling.
"""
import math
from typing import Dict, List, Union

Coeff = Union[float, List[float]]

# CVSS 3.1 metric coefficients
COEFF: Dict[str, Dict[str, Coeff]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    # [0] Scope Changed, [1] Scope Unchanged
    "PR": {"N": 0.85, "L": [0.68, 0.62], "H": [0.50, 0.27]},
    "UI": {"N": 0.85, "R": 0.62},
    "S":  {"U": 6.42, "C": 7.52},
    "C":  {"N": 0.00, "L": 0.22, "H": 0.56},
    "I":  {"N": 0.00, "L": 0.22, "H": 0.56},
    "A":  {"N": 0.00, "L": 0.22, "H": 0.56},
}

VECTOR_ORDER = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]


def base_score(vector: str) -> float:
    """Return the CVSS v3.1 Base score rounded up to one decimal place."""
    parts = dict(field.split(":") for field in vector.split("/")[1:])
    coeffs = {k: COEFF[k][v] for k, v in parts.items()}

    iss = 1 - (1 - coeffs["C"]) * (1 - coeffs["I"]) * (1 - coeffs["A"])

    if parts["S"] == "U":  # Unchanged Scope
        pr = coeffs["PR"] if parts["PR"] == "N" else coeffs["PR"][1]
        exploitability = 8.22 * coeffs["AV"] * coeffs["AC"] * pr * coeffs["UI"]
        impact = 6.42 * iss
        score = min(exploitability + impact, 10)
    else:                  # Changed Scope
        pr = coeffs["PR"] if parts["PR"] == "N" else coeffs["PR"][0]
        exploitability = 8.22 * coeffs["AV"] * coeffs["AC"] * pr * coeffs["UI"]
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        score = 1.08 * (exploitability + impact)

    if impact <= 0:
        return 0.0
    return min(10.0, math.ceil(score * 10) / 10)


if __name__ == "__main__":
    # Quick self‑test
    print(base_score("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"))
