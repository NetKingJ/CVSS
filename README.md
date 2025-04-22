# CVSS

## CVE CVSS Extractor
- Extracts CVSS 4.0 and CVSS 3.1 vector strings from CVE data.
- Data Source: [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5.git)

## CVSS Calculator
- Implements CVSS score calculation logic directly, without relying on external CVSS libraries.

## CVSS Metric Influence
- Calculates the impact (weights) of each metric on the final CVSS score, by version.

## Generate CVSS Vectors
- Generates all possible metric combinations for each CVSS version to produce every valid vector string.
