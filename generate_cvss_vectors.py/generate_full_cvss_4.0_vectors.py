# Generate all possible CVSS 4.0 combinations
from itertools import product
from cvss import CVSS4

AV = ['N', 'A', 'L', 'P']
AC = ['L', 'H']
AT = ['N', 'P']
PR = ['N', 'L', 'H']
UI = ['N', 'P', 'A']
VC = ['H', 'L', 'N']
VI = ['H', 'L', 'N']
VA = ['H', 'L', 'N']
SC = ['H', 'L', 'N']
SI = ['H', 'L', 'N']
SA = ['H', 'L', 'N']

S = ['X', 'N', 'P']       # Safety
AU = ['X', 'N', 'Y']      # Automatable
R = ['X', 'A', 'U', 'I']  # Recovery
V = ['X', 'D', 'C']       # Value Density
RE = ['X', 'L', 'M', 'H'] # Vulnerability Response Effort
U = ['X', 'Clear', 'Green', 'Amber', 'Red']  # Provider Urgency
E = ['X', 'A', 'P', 'U']  # Exploit Maturity

# Generate all combinations including extended metrics
all_combinations = product(AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA, S, AU, R, V, RE, U, E)

# Save results to a file
with open('cvss4.0_combinations.txt', 'w') as f:
    for combination in all_combinations:
        vector = f"CVSS:4.0/AV:{combination[0]}/AC:{combination[1]}/AT:{combination[2]}/PR:{combination[3]}/UI:{combination[4]}/VC:{combination[5]}/VI:{combination[6]}/VA:{combination[7]}/SC:{combination[8]}/SI:{combination[9]}/SA:{combination[10]}/S:{combination[11]}/AU:{combination[12]}/R:{combination[13]}/V:{combination[14]}/RE:{combination[15]}/U:{combination[16]}/E:{combination[17]}"
        cvss = CVSS4(vector)
        score = cvss.scores()[0]
        macro_vector = cvss.macroVector()  # Include macro vector (currently unused)
        # f.write(f"{vector}\t{score}\t{macro_vector}\n")
        f.write(f"{score}\n")
