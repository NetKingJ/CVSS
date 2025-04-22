"""
Generate every CVSS 4.0 base‑metric combination, calculate its base score
(and macro vector), and save each result to cvss_4.0_(CVSS-B)_combinations.txt.
"""

from itertools import product
from cvss import CVSS4

# Base‑metric value lists (order matters)
AV = ['N', 'A', 'L', 'P']   # Attack Vector
AC = ['L', 'H']             # Attack Complexity
AT = ['N', 'P']             # Attack Requirements (Threat)
PR = ['N', 'L', 'H']        # Privileges Required
UI = ['N', 'P', 'A']        # User Interaction
VC = ['H', 'L', 'N']        # Vulnerable Confidentiality
VI = ['H', 'L', 'N']        # Vulnerable Integrity
VA = ['H', 'L', 'N']        # Vulnerable Availability
SC = ['H', 'L', 'N']        # Subsequent Confidentiality
SI = ['H', 'L', 'N']        # Subsequent Integrity
SA = ['H', 'L', 'N']        # Subsequent Availability

with open('cvss_4.0_(CVSS-B)_combinations.txt', 'w', encoding='utf-8') as f:
    for (av, ac, at, pr, ui, vc, vi, va, sc, si, sa) in product(AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA):
        vector = (
            f"CVSS:4.0/AV:{av}/AC:{ac}/AT:{at}/PR:{pr}/UI:{ui}/"
            f"VC:{vc}/VI:{vi}/VA:{va}/SC:{sc}/SI:{si}/SA:{sa}"
        )
        cvss = CVSS4(vector)
        score = cvss.scores()[0]          # Base score
        macro = cvss.macroVector()        # Macro vector (high‑level summary)
        f.write(f"{vector}\t{score}\n")
