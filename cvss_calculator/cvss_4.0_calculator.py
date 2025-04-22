"""
Developer : Vulnerability Analysis Team, Seung‑Hyun Cho
Purpose   : CVSS 4.0 score calculation
Last mod  : 2024‑01‑26 (Fri)

CVSS 4.0 calculation procedure
1) Parse the CVSS vector
2) Calculate the base score
3) Determine the maximum value for each metric
4) Calculate the metric‑level severity score
5) Compute the average score‑reduction distance
6) Derive the final score
"""

# BASE_SCORE: CVSS 4.0 base scores (lookup table produced from the specification)
BASE_SCORE = {
    '000000': 10, '000001': 9.9, '000010': 9.8, '000011': 9.5, '000020': 9.5, '000021': 9.2, '000100': 10,
    '000101': 9.6, '000110': 9.3, '000111': 8.7, '000120': 9.1, '000121': 8.1, '000200': 9.3, '000201': 9,
    '000210': 8.9, '000211': 8, '000220': 8.1, '000221': 6.8, '001000': 9.8, '001001': 9.5, '001010': 9.5,
    '001011': 9.2, '001020': 9, '001021': 8.4, '001100': 9.3, '001101': 9.2, '001110': 8.9, '001111': 8.1,
    '001120': 8.1, '001121': 6.5, '001200': 8.8, '001201': 8, '001210': 7.8, '001211': 7, '001220': 6.9,
    '001221': 4.8, '002001': 9.2, '002011': 8.2, '002021': 7.2, '002101': 7.9, '002111': 6.9, '002121': 5,
    '002201': 6.9, '002211': 5.5, '002221': 2.7, '010000': 9.9, '010001': 9.7, '010010': 9.5, '010011': 9.2,
    '010020': 9.2, '010021': 8.5, '010100': 9.5, '010101': 9.1, '010110': 9, '010111': 8.3, '010120': 8.4,
    '010121': 7.1, '010200': 9.2, '010201': 8.1, '010210': 8.2, '010211': 7.1, '010220': 7.2, '010221': 5.3,
    '011000': 9.5, '011001': 9.3, '011010': 9.2, '011011': 8.5, '011020': 8.5, '011021': 7.3, '011100': 9.2,
    '011101': 8.2, '011110': 8, '011111': 7.2, '011120': 7, '011121': 5.9, '011200': 8.4, '011201': 7,
    '011210': 7.1, '011211': 5.2, '011220': 5, '011221': 3, '012001': 8.6, '012011': 7.5, '012021': 5.2,
    '012101': 7.1, '012111': 5.2, '012121': 2.9, '012201': 6.3, '012211': 2.9, '012221': 1.7, '100000': 9.8,
    '100001': 9.5, '100010': 9.4, '100011': 8.7, '100020': 9.1, '100021': 8.1, '100100': 9.4, '100101': 8.9,
    '100110': 8.6, '100111': 7.4, '100120': 7.7, '100121': 6.4, '100200': 8.7, '100201': 7.5, '100210': 7.4,
    '100211': 6.3, '100220': 6.3, '100221': 4.9, '101000': 9.4, '101001': 8.9, '101010': 8.8, '101011': 7.7,
    '101020': 7.6, '101021': 6.7, '101100': 8.6, '101101': 7.6, '101110': 7.4, '101111': 5.8, '101120': 5.9,
    '101121': 5, '101200': 7.2, '101201': 5.7, '101210': 5.7, '101211': 5.2, '101220': 5.2, '101221': 2.5,
    '102001': 8.3, '102011': 7, '102021': 5.4, '102101': 6.5, '102111': 5.8, '102121': 2.6, '102201': 5.3,
    '102211': 2.1, '102221': 1.3, '110000': 9.5, '110001': 9, '110010': 8.8, '110011': 7.6, '110020': 7.6,
    '110021': 7, '110100': 9, '110101': 7.7, '110110': 7.5, '110111': 6.2, '110120': 6.1, '110121': 5.3,
    '110200': 7.7, '110201': 6.6, '110210': 6.8, '110211': 5.9, '110220': 5.2, '110221': 3, '111000': 8.9,
    '111001': 7.8, '111010': 7.6, '111011': 6.7, '111020': 6.2, '111021': 5.8, '111100': 7.4, '111101': 5.9,
    '111110': 5.7, '111111': 5.7, '111120': 4.7, '111121': 2.3, '111200': 6.1, '111201': 5.2, '111210': 5.7,
    '111211': 2.9, '111220': 2.4, '111221': 1.6, '112001': 7.1, '112011': 5.9, '112021': 3, '112101': 5.8,
    '112111': 2.6, '112121': 1.5, '112201': 2.3, '112211': 1.3, '112221': 0.6, '200000': 9.3, '200001': 8.7,
    '200010': 8.6, '200011': 7.2, '200020': 7.5, '200021': 5.8, '200100': 8.6, '200101': 7.4, '200110': 7.4,
    '200111': 6.1, '200120': 5.6, '200121': 3.4, '200200': 7, '200201': 5.4, '200210': 5.2, '200211': 4,
    '200220': 4, '200221': 2.2, '201000': 8.5, '201001': 7.5, '201010': 7.4, '201011': 5.5, '201020': 6.2,
    '201021': 5.1, '201100': 7.2, '201101': 5.7, '201110': 5.5, '201111': 4.1, '201120': 4.6, '201121': 1.9,
    '201200': 5.3, '201201': 3.6, '201210': 3.4, '201211': 1.9, '201220': 1.9, '201221': 0.8, '202001': 6.4,
    '202011': 5.1, '202021': 2, '202101': 4.7, '202111': 2.1, '202121': 1.1, '202201': 2.4, '202211': 0.9,
    '202221': 0.4, '210000': 8.8, '210001': 7.5, '210010': 7.3, '210011': 5.3, '210020': 6, '210021': 5,
    '210100': 7.3, '210101': 5.5, '210110': 5.9, '210111': 4, '210120': 4.1, '210121': 2, '210200': 5.4,
    '210201': 4.3, '210210': 4.5, '210211': 2.2, '210220': 2, '210221': 1.1, '211000': 7.5, '211001': 5.5,
    '211010': 5.8, '211011': 4.5, '211020': 4, '211021': 2.1, '211100': 6.1, '211101': 5.1, '211110': 4.8,
    '211111': 1.8, '211120': 2, '211121': 0.9, '211200': 4.6, '211201': 1.8, '211210': 1.7, '211211': 0.7,
    '211220': 0.8, '211221': 0.2, '212001': 5.3, '212011': 2.4, '212021': 1.4, '212101': 2.4, '212111': 1.2,
    '212121': 0.5, '212201': 1, '212211': 0.3, '212221': 0.1
}

# LEVELS: per‑metric component scores (lower is better / more severe)
LEVELS = {
    'AV': {'N': 0.0, 'A': 0.1, 'L': 0.2, 'P': 0.3},
    'PR': {'N': 0.0, 'L': 0.1, 'H': 0.2},
    'UI': {'N': 0.0, 'P': 0.1, 'A': 0.2},
    'AC': {'L': 0.0, 'H': 0.1},
    'AT': {'N': 0.0, 'P': 0.1},
    'VC': {'H': 0.0, 'L': 0.1, 'N': 0.2},
    'VI': {'H': 0.0, 'L': 0.1, 'N': 0.2},
    'VA': {'H': 0.0, 'L': 0.1, 'N': 0.2},
    'SC': {'H': 0.1, 'L': 0.2, 'N': 0.3},
    'SI': {'S': 0.0, 'H': 0.1, 'L': 0.2, 'N': 0.3},
    'SA': {'S': 0.0, 'H': 0.1, 'L': 0.2, 'N': 0.3},
    'CR': {'H': 0.0, 'M': 0.1, 'L': 0.2},
    'IR': {'H': 0.0, 'M': 0.1, 'L': 0.2},
    'AR': {'H': 0.0, 'M': 0.1, 'L': 0.2},
    'E' : {'U': 0.2, 'P': 0.1, 'A': 0.0}
}

class CVSS4Vector:
    """Represent a CVSS 4.0 vector and provide convenient access helpers."""

    # Complete list of metric keys (including environmental modifiers)
    keys = ['AV', 'PR', 'UI', 'AC', 'AT', 'VC', 'VI', 'VA',
            'SC', 'SI', 'SA', 'MSI', 'MSA', 'CR', 'IR', 'AR', 'E']

    def __init__(self, vector: str, partial: bool = False):
        """Parse *vector* (e.g. ``CVSS:4.0/AV:N/AC:H/...``). If *partial* is
        True the string is treated as a fragment that already omits the
        ``CVSS:4.0/`` prefix."""
        self.vector = vector.strip('/')  # keep the raw string (minus trailing '/')

        # Initialise storage for each key with None
        self._data = dict(zip(self.keys, [None] * len(self.keys)))

        # Split the string into "key:value" components
        parts = self.vector.split('/')[1:] if not partial else self.vector.split('/')
        for part in parts:
            name, value = part.split(':')
            self._data[name] = value

    def __str__(self):
        return self.vector

    def get(self, key: str):
        """Return the metric value for *key*, applying CVSS defaulting rules."""
        value = self._data.get(key)
        if not value or value == 'X':
            # Apply specification defaults
            if key == 'E':
                return 'A'  # Exploitability not defined -> assume Attacked
            if key in ['CR', 'IR', 'AR']:
                return 'H'  # Security requirement undefined -> assume High
        # Environmental metrics (prefixed with 'M') override base metrics
        modified = self._data.get(f'M{key}')
        if modified:
            return modified
        return value

    def asdict(self, kfilter=None):
        """Return the vector as a ``dict``; optionally filter by *kfilter*."""
        data = {}
        for k in self.keys:
            if kfilter is None or k in kfilter:
                data[k] = self.get(k)
        return data


class EQManager:
    """Manage the six EQ evaluation blocks used by the specification."""

    def __init__(self, vector: CVSS4Vector):
        self._vector = vector
        self.eqs = [EQ1(vector), EQ2(vector), EQ3(vector), EQ4(vector), EQ5(vector), EQ6(vector)]
        # EQ3 and EQ6 are coupled in the algorithm
        self._eq3eq6 = EQ3EQ6(self.eqs[2], self.eqs[5])

    @property
    def value(self):
        """Concatenate the individual EQ values into a lookup string."""
        return ''.join(str(x) for x in self.eqs)

    @property
    def maxes(self):
        """Return a CVSS4Vector that corresponds to the maximum‑score combination."""
        return CVSS4Vector(f'{self.eq(1).maxes[0]}{self.eq(2).maxes[0]}{self.eq(3).maxes[0]}{self.eq(4).maxes[0]}{self.eq(5).maxes[0]}', partial=True)

    def eq(self, eq: int, direct: bool = False):
        """Return the *eq*‑th EQ object (1‑based). ``direct`` skips EQ3/EQ6 coupling."""
        if eq == 3 and not direct:
            return self._eq3eq6
        return self.eqs[eq - 1]

    # Convenience helpers used by the scoring algorithm --------------------

    def nextLower(self, eq: int):
        """Return the lookup key for the next‑lower score when *eq* is reduced."""
        values = [x.value for x in self.eqs]
        if eq == 3:  # special coupling logic between EQ3 and EQ6
            eq3 = values[2]
            eq6 = values[5]
            if eq3 in [0, 1] and eq6 == 1:
                values[2] += 1
                return ''.join(str(x) for x in values)
            if eq3 == 1 and eq6 == 0:
                values[5] += 1
                return ''.join(str(x) for x in values)
            if eq3 == 0 and eq6 == 0:
                # Both adjustable – choose the path that reduces the score more
                l_values = list(values)
                l_values[5] += 1
                l_value = ''.join(str(x) for x in l_values)
                r_values = list(values)
                r_values[2] += 1
                r_value = ''.join(str(x) for x in r_values)
                l_score = BASE_SCORE.get(l_value)
                r_score = BASE_SCORE.get(r_value)
                if l_score and r_score and l_score > r_score:
                    return l_value
                return r_value
        # Simple case: bump the requested EQ one level lower
        values[eq - 1] += 1
        return ''.join(str(x) for x in values)

    def nextLowerScore(self, eq: int):
        """Return the numeric score of the next‑lower combination for *eq*."""
        return BASE_SCORE.get(self.nextLower(eq))

    def maxSeverity(self, eq: int):
        """Return the maximum possible severity for EQ *eq*."""
        return self.eq(eq).max_severity


# Internal EQ helper base class -------------------------------------------

class _EQ:
    """Abstract base class for individual EQ evaluators."""

    vector_keys: list[str] = []  # metrics used by this EQ
    _maxes: dict[int, list[str]] = {}  # mapping: value -> list of max vectors
    _severity: dict[int, int] = {}     # mapping: value -> severity weight (×0.1)

    def __init__(self, vector: CVSS4Vector):
        self._vector = vector
        self._values = vector.asdict(self.vector_keys)

    def __str__(self):
        return str(self.value)

    @property
    def maxes(self):
        return self._maxes[self.value]

    @property
    def max_severity(self):
        return self._severity[self.value] * 0.1

    # ---------------------------------------------------------------------
    def _fvalues(self, keys):
        """Return a filtered dict containing only *keys*."""
        return {k: v for k, v in self._values.items() if k in keys}


# Concrete EQ implementations --------------------------------------------

class EQ1(_EQ):
    """EQ1 evaluates AV, PR, UI."""

    vector_keys = ['AV', 'PR', 'UI']
    _maxes = {
        0: ['AV:N/PR:N/UI:N/'],
        1: ['AV:A/PR:N/UI:N/'],
        2: ['AV:P/PR:N/UI:N/']
    }
    _severity = {0: 1, 1: 4, 2: 5}

    @property
    def value(self):
        if all(x == 'N' for x in self._values.values()):
            return 0
        if any(x == 'N' for x in self._values.values()) and self._values['AV'] != 'P':
            return 1
        return 2


class EQ2(_EQ):
    """EQ2 evaluates AC, AT."""

    vector_keys = ['AC', 'AT']
    _maxes = {0: ['AC:L/AT:N/'], 1: ['AC:H/AT:N/']}
    _severity = {0: 1, 1: 2}

    @property
    def value(self):
        if self._values['AC'] == 'L' and self._values['AT'] == 'N':
            return 0
        return 1


class EQ3(_EQ):
    """EQ3 evaluates VC, VI, VA."""

    vector_keys = ['VC', 'VI', 'VA']

    @property
    def value(self):
        if all(x == 'H' for x in self._fvalues(['VC', 'VI']).values()):
            return 0
        if any(x == 'H' for x in self._values.values()):
            return 1
        return 2


class EQ4(_EQ):
    """EQ4 evaluates MSI, MSA, SC, SI, SA."""

    vector_keys = ['MSI', 'MSA', 'SC', 'SI', 'SA']
    _maxes = {
        0: ['SC:H/SI:S/SA:S/'],
        1: ['SC:H/SI:H/SA:H/'],
        2: ['SC:L/SI:L/SA:L/']
    }
    _severity = {0: 6, 1: 5, 2: 4}

    @property
    def value(self):
        if any(x == 'S' for x in self._fvalues(['MSI', 'MSA']).values()):
            return 0
        if any(x == 'H' for x in self._fvalues(['SC', 'SI', 'SA']).values()):
            return 1
        return 2


class EQ5(_EQ):
    """EQ5 evaluates E (Exploitability)."""

    vector_keys = ['E']
    _maxes = {0: ['E:A/'], 1: ['E:P/'], 2: ['E:U/']}
    _severity = {0: 1, 1: 1, 2: 1}

    @property
    def value(self):
        value = self._values['E']
        if value == 'A':
            return 0
        if value == 'P':
            return 1
        return 2


class EQ6(_EQ):
    """EQ6 evaluates CR, IR, AR in conjunction with VC, VI, VA."""

    vector_keys = ['CR', 'IR', 'AR', 'VC', 'VI', 'VA']

    @property
    def value(self):
        if (all(x == 'H' for x in self._fvalues(['CR', 'VC']).values()) or
            all(x == 'H' for x in self._fvalues(['IR', 'VI']).values()) or
            all(x == 'H' for x in self._fvalues(['AR', 'VA']).values())):
            return 0
        return 1


# Coupled evaluator for EQ3 + EQ6 ----------------------------------------

class EQ3EQ6:
    """Combine EQ3 and EQ6 into a single severity representation."""

    _maxes = {
        0: {
            0: ['VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/'],
            1: ['VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/']
        },
        1: {
            0: ['VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/'],
            1: ['VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/']
        },
        2: {
            1: ['VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/']
        }
    }

    _severity = {
        0: {0: 7, 1: 6},
        1: {0: 8, 1: 8},
        2: {1: 10}
    }

    def __init__(self, eq3: EQ3, eq6: EQ6):
        self._eq3 = eq3
        self._eq6 = eq6

    @property
    def maxes(self):
        return self._maxes[self._eq3.value][self._eq6.value]

    @property
    def max_severity(self):
        return self._severity[self._eq3.value][self._eq6.value] * 0.1


# Main public API ---------------------------------------------------------

class CVSS4Calculator:
    """High‑level CVSS 4.0 score calculator."""

    @classmethod
    def calc(cls, vector):
        """Calculate the CVSS 4.0 score for *vector* (string or CVSS4Vector)."""
        if isinstance(vector, str):
            vector = CVSS4Vector(vector)

        # Early exit: no impact at all ➜ score 0.0
        none_check = ['VC', 'VI', 'VA', 'SC', 'SI', 'SA']
        vector_dict = vector.asdict()
        if all(vector_dict.get(key) == 'N' for key in none_check):
            return 0.0

        # -----------------------------------------------------------------
        eqmanager = EQManager(vector)
        value = BASE_SCORE[eqmanager.value]

        # Compute severity deltas against the maximum‑score vector
        severity = {}
        for key in CVSS4Vector.keys:
            if key in ['MSI', 'MSA']:
                continue
            vector_value, max_value = vector_dict.get(key), eqmanager.maxes.get(key)
            if max_value:
                severity[key] = round(LEVELS[key][vector_value] - LEVELS[key][max_value], 2)
            else:
                severity[key] = LEVELS[key][vector_value]

        # Aggregate severities per EQ block
        current_severities = [
            round(sum(severity[key] for key in ['AV', 'PR', 'UI']), 2),  # EQ1
            round(sum(severity[key] for key in ['AC', 'AT']), 2),        # EQ2
            round(sum(severity[key] for key in ['VC', 'VI', 'VA', 'CR', 'IR', 'AR']), 2),  # EQ3+EQ6
            round(sum(severity[key] for key in ['SC', 'SI', 'SA']), 2),  # EQ4
            0  # EQ5 has no severity delta
        ]

        # Compute available score‑reduction distances for each EQ
        available_distances = []
        for eq in range(1, 6):
            lower_score = eqmanager.nextLowerScore(eq)
            if lower_score is not None:
                available_distances.append(round(value - lower_score, 2))
            else:
                available_distances.append(None)

        # Normalise the distances using the current severity weights
        normalized = []
        for i, distance in enumerate(available_distances):
            if distance:
                normalized_value = round(distance * current_severities[i] / eqmanager.maxSeverity(i + 1), 2)
                normalized.append(normalized_value)
            else:
                normalized.append(0)

        # -----------------------------------------------------------------
        # Compute mean score‑reduction distance (excluding Nones)
        existing_lower = sum(1 for d in available_distances if d is not None)
        mean_distance = round(sum(normalized) / existing_lower, 2) if existing_lower else 0

        # Final score adjustment and clamping
        adjusted_value = max(min(round(value - mean_distance, 2), 10.0), 0.0)
        return round(float(adjusted_value), 1)


if __name__ == '__main__':
    # Example usage
    vector = (
        'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:H/SC:N/SI:H/SA:N/E:A/CR:H/AR:L/MAV:L/MAC:L/MAT:N/MPR:H/MUI:P/MVC:N/MVI:L/MVA:H/MSC:L/MSI:H/MSA:S/S:P/AU:N/R:I/V:C/RE:L/U:Amber'
    )
    score = CVSS4Calculator.calc(vector)
    print(score)
