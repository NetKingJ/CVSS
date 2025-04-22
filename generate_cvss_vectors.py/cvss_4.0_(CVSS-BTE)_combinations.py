"""
Enumerate every CVSS 4.0 CVSS-BTE vector, compute its base score,
and write each score to cvss_4.0_(CVSS-BTE)_combinations.txt.
"""

from itertools import product
from cvss import CVSS4

# Base metrics
AV = ['N', 'A', 'L', 'P']          # Attack Vector
AC = ['L', 'H']                    # Attack Complexity
AT = ['N', 'P']                    # Attack Requirements
PR = ['N', 'L', 'H']               # Privileges Required
UI = ['N', 'P', 'A']               # User Interaction
VC = ['H', 'L', 'N']               # Vulnerable Confidentiality
VI = ['H', 'L', 'N']               # Vulnerable Integrity
VA = ['H', 'L', 'N']               # Vulnerable Availability
SC = ['H', 'L', 'N']               # Subsequent Confidentiality
SI = ['H', 'L', 'N']               # Subsequent Integrity
SA = ['H', 'L', 'N']               # Subsequent Availability

# Supplemental metrics
S  = ['X', 'N', 'P']                              # Safety
AU = ['X', 'N', 'Y']                              # Automatable
R  = ['X', 'A', 'U', 'I']                         # Recovery
V  = ['X', 'D', 'C']                              # Value Density
RE = ['X', 'L', 'M', 'H']                         # Response Effort
U  = ['X', 'Clear', 'Green', 'Amber', 'Red']      # Urgency
E  = ['X', 'A', 'P', 'U']                         # Exploit Maturity

with open('cvss_4.0_(CVSS-BTE)_combinations.txt', 'w', encoding='utf-8') as f:
    for (av, ac, at, pr, ui, vc, vi, va, sc, si, sa, s, au, r, v, re, u, e) in product(AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA, S, AU, R, V, RE, U, E):
        vector = (
            f"CVSS:4.0/AV:{av}/AC:{ac}/AT:{at}/PR:{pr}/UI:{ui}/"
            f"VC:{vc}/VI:{vi}/VA:{va}/SC:{sc}/SI:{si}/SA:{sa}/"
            f"S:{s}/AU:{au}/R:{r}/V:{v}/RE:{re}/U:{u}/E:{e}"
        )
        cvss = CVSS4(vector)
        score = cvss.scores()[0]          # Base score
        macro = cvss.macroVector()        # Macro vector (high‑level summary)
        f.write(f"{vector}\t{score}\n")