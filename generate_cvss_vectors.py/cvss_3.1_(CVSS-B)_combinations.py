"""
Generate every CVSS 3.1 base‑metric combination, calculate its base score,
and save each vector‑score pair to cvss_3.1_(CVSS-B)_combinations.txt.
"""

from itertools import product
from cvss import CVSS3

# Base‑metric value lists (order matters)
AV = ['N', 'A', 'L', 'P']  # Attack Vector
AC = ['L', 'H']            # Attack Complexity
PR = ['N', 'L', 'H']       # Privileges Required
UI = ['N', 'R']            # User Interaction
S  = ['U', 'C']            # Scope
C  = ['H', 'L', 'N']       # Confidentiality
I  = ['H', 'L', 'N']       # Integrity
A  = ['H', 'L', 'N']       # Availability

with open('cvss_3.1_(CVSS-B)_combinations.txt', 'w', encoding='utf-8') as f:
    for av, ac, pr, ui, s, c, i, a in product(AV, AC, PR, UI, S, C, I, A):
        vector = (
            f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/"
            f"C:{c}/I:{i}/A:{a}"
        )
        score = CVSS3(vector).scores()[0]  # Base score
        f.write(f"{vector}\t{score}\n")
