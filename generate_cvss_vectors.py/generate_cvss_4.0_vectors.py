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

# Generate all possible combinations of CVSS 4.0 base metrics
all_combinations = product(AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA)

# Save results to a file
with open('cvss4.0_combinations.txt', 'w') as f:
    for combination in all_combinations:
        vector = f"CVSS:4.0/AV:{combination[0]}/AC:{combination[1]}/AT:{combination[2]}/PR:{combination[3]}/UI:{combination[4]}/VC:{combination[5]}/VI:{combination[6]}/VA:{combination[7]}/SC:{combination[8]}/SI:{combination[9]}/SA:{combination[10]}"
        cvss = CVSS4(vector)
        score = cvss.scores()[0]
        macro_vector = cvss.macroVector()  # Include macro vector
        f.write(f"{vector}\t{score}\n")
