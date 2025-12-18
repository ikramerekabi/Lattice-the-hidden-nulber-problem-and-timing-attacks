#!/usr/bin/env python3
"""
Table-based evaluation of the timing + lattice attack.

Sweeps:
- bits: attacker nonce-size assumption
- N: number of collected signatures

Outputs:
- Console table (SUCCESS / FAILURE)
- Optional CSV file
"""

import subprocess
import re
import csv

############################################
# PARAMETERS
############################################

BITS_VALUES = [6, 8, 10, 12, 14, 16]
SIGNATURE_COUNTS = [50, 75, 100, 150]

ATTACK_SCRIPT = "lattice_timing_attack.py"
SAGE_SCRIPT = "lattice_data.sage"

CSV_OUTPUT = "bits_vs_signatures_results.csv"

############################################
# REGEX HELPERS
############################################

TRUE_KEY_RE = re.compile(r"True private key .*?: (\d+)")
RECOVERED_KEY_RE = re.compile(r"KEY_RESULT\s*=\s*(\d+)")

############################################
# RUN EXPERIMENTS
############################################

# results[(bits, N)] = 0 or 1
results = {}

for bits in BITS_VALUES:
    for N in SIGNATURE_COUNTS:
        print(f"Running bits={bits}, signatures={N}...")

        # Run Python attack
        proc = subprocess.run(
            ["python3", ATTACK_SCRIPT,
             "--bits", str(bits),
             "--signatures", str(N)],
            capture_output=True,
            text=True
        )

        py_out = proc.stdout
        true_key_match = TRUE_KEY_RE.search(py_out)

        if not true_key_match:
            results[(bits, N)] = 0
            continue

        true_key = int(true_key_match.group(1))

        # Run Sage
        proc = subprocess.run(
            ["sage", SAGE_SCRIPT],
            capture_output=True,
            text=True
        )

        sage_out = proc.stdout
        recovered_key_match = RECOVERED_KEY_RE.search(sage_out)

        if not recovered_key_match:
            results[(bits, N)] = 0
            continue

        recovered_key = int(recovered_key_match.group(1))
        results[(bits, N)] = int(recovered_key == true_key)

############################################
# PRINT TABLE
############################################

print("\nAttack success table (✓ = success, ✗ = failure)\n")

# Header
header = ["bits \\ N"] + [str(N) for N in SIGNATURE_COUNTS]
print("{:>10}".format(header[0]), end="")
for h in header[1:]:
    print("{:>8}".format(h), end="")
print()

# Rows
for bits in BITS_VALUES:
    print("{:>10}".format(bits), end="")
    for N in SIGNATURE_COUNTS:
        cell = "✓" if results[(bits, N)] else "✗"
        print("{:>8}".format(cell), end="")
    print()

############################################
# SAVE CSV (OPTIONAL BUT RECOMMENDED)
############################################

with open(CSV_OUTPUT, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(header)
    for bits in BITS_VALUES:
        row = [bits] + [
            "SUCCESS" if results[(bits, N)] else "FAILURE"
            for N in SIGNATURE_COUNTS
        ]
        writer.writerow(row)

print(f"\nResults saved to {CSV_OUTPUT}")
