from itertools import product
from cvss import CVSS3

AV = ['N', 'A', 'L', 'P']
AC = ['L', 'H']
PR = ['N', 'L', 'H']
UI = ['N', 'R']
S = ['U', 'C']
C = ['H', 'L', 'N']
I = ['H', 'L', 'N']
A = ['H', 'L', 'N']

# Generate all possible combinations of CVSS 3.1 base metrics
all_combinations = product(AV, AC, PR, UI, S, C, I, A)

# Save results to a file
with open('cvss3.1_combinations.txt', 'w') as f:
    for combination in all_combinations:
        vector = f"CVSS:3.1/AV:{combination[0]}/AC:{combination[1]}/PR:{combination[2]}/UI:{combination[3]}/S:{combination[4]}/C:{combination[5]}/I:{combination[6]}/A:{combination[7]}"
        cvss = CVSS3(vector)
        score = cvss.scores()[0]
        f.write(f"{vector}\t{score}\n")
