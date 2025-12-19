#!/usr/bin/env python3
import argparse
import json
import random
import numpy as np
from sklearn.cluster import KMeans
import subprocess
import re
import os

# reads the JSON file and selects candidates (which at the moment is all records)
def read_and_select_candidates(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    
    records = data['records']
    q = data['meta']['q']
    
    # extracting times and indices
    times = np.array([r['time_taken'] for r in records])
    indices = np.array([r['index'] for r in records])
    
    print(f"Timing statistics: min={times.min():.2f}, max={times.max():.2f}, mean={times.mean():.2f}")

    candidates = indices.tolist()
    print(f"Using all {len(candidates)} records as candidates...\n")
    return candidates, records, int(q)

############################################
# Lattice Attack Preparation (Python-only part)
############################################

def prepare_lattice_attack_data(digests, signatures, modulo, bits):
    """Prepare the data for lattice attack (Python-only part)"""
    
    if len(digests) < 2:
        print("Need at least 2 signatures for attack")
        return None

    # building Equations - getting rid of the first equation
    r0_inv = pow(signatures[0][0], -1, modulo)
    s0 = signatures[0][1]
    m0 = digests[0]
    
    AA = [-1]
    BB = [0]
    nn = len(digests)
    
    print(f"Preparing lattice of size {nn + 1}")
    
    for ii in range(1, nn):
        mm = digests[ii]
        rr = signatures[ii][0]
        ss = signatures[ii][1]
        ss_inv = pow(ss, -1, modulo)
        
        AA_i = (-1 * s0 * r0_inv * rr * ss_inv) % modulo
        BB_i = (-1 * mm * ss_inv + m0 * r0_inv * rr * ss_inv) % modulo
        AA.append(AA_i)
        BB.append(BB_i)

    # calculate trick value
    trick = int(modulo / 2**(bits + 1))
    
    attack_data = {
        'AA': AA,
        'BB': BB,
        'modulo': modulo,
        'trick': trick,
        'first_signature': signatures[0],
        'first_digest': digests[0],
        'num_signatures': nn
    }
    
    return attack_data

def save_lattice_data_for_sage(attack_data, filename="lattice_data.sage"):
    """Save the prepared data in a format that Sage can read"""
    with open(filename, 'w') as f:
        f.write(f"# Sage script for lattice attack\n")
        f.write(f"# Generated from Python preparation\n\n")
        
        f.write(f"modulo = {attack_data['modulo']}\n")
        f.write(f"trick = {attack_data['trick']}\n")
        f.write(f"nn = {attack_data['num_signatures']}\n\n")
        
        f.write(f"AA = {attack_data['AA']}\n")
        f.write(f"BB = {attack_data['BB']}\n\n")
        
        f.write(f"first_r = {attack_data['first_signature'][0]}\n")
        f.write(f"first_s = {attack_data['first_signature'][1]}\n")
        f.write(f"first_m = {attack_data['first_digest']}\n\n")
        
        # write the Sage lattice attack code
        f.write("""
# Embedding Technique (CVP->SVP)
if trick != -1:
    lattice = Matrix(ZZ, nn + 1)
else:
    lattice = Matrix(ZZ, nn)

# Fill lattice
for ii in range(nn):
    lattice[ii, ii] = modulo
    lattice[0, ii] = AA[ii]

# Add trick
if trick != -1:
    print(f"Adding trick: {trick}")
    BB.append(trick)
    lattice[nn] = vector(BB)
else:
    print("Not adding any trick")

print("Using LLL reduction")
lattice = lattice.LLL()

# Check if solution is found
if trick == -1 or Mod(lattice[0,-1], modulo) == trick or Mod(lattice[0,-1], modulo) == Mod(-trick, modulo):
    print("Solution found in lattice!")
    
    # did we found trick or -trick?
    if trick != -1:
        # trick
        if Mod(lattice[0,-1], modulo) == trick:
            solution = -1 * lattice[0] - vector(BB)
        # -trick
        else:
            print("We found a -trick instead of a trick")
            solution = lattice[0] + vector(BB)
    else:
        solution = -1 * lattice[0] - vector(BB)

    # get rid of (..., trick) if we used the trick
    if trick != -1:
        vec = list(solution)
        vec.pop()
        solution = vector(vec)

    # recover private key
    nonce = solution[0]
    key = Mod((first_s * nonce - first_m) * inverse_mod(first_r, modulo), modulo)
    
    print(f"Recovered private key candidate: {key}")
    print(f"KEY_RESULT = {key}")
else:
    print("No solution found in lattice")
    print("KEY_RESULT = 0")
""")
    
    print(f"Saved Sage script to {filename}")
    return filename

def run_sage_script(sage_filename):
    """Execute the Sage script and extract the recovered key"""
    print(f"\n5. Running Sage script: {sage_filename}")
    print("="*50)
    
    # Run the sage script
    result = subprocess.run(['sage', sage_filename], 
                            capture_output=True, 
                            text=True, 
                            timeout=60)
    
    print("Sage output:")
    print(result.stdout)
    
    if result.stderr:
        print("Sage errors:")
        print(result.stderr)
    
    match = re.search(r'KEY_RESULT\s*=\s*(\d+)', result.stdout)
    
    if match:
        recovered_key = int(match.group(1))
        if recovered_key == 0:
            print("\nSage did not find a valid key (KEY_RESULT = 0)")
            return None
        print(f"\nExtracted recovered key: {recovered_key}")
        return recovered_key
    else:
        print("\nCould not extract KEY_RESULT from Sage output")
        return None

############################################
# Complete Attack Pipeline
############################################

def execute_complete_attack(bits=8):
    candidates, attacker_records, q = read_and_select_candidates(
        'attacker_view.json'
    )
    
    # Step 3: Prepare data for lattice attack
    print("\n3. Preparing data for lattice attack...")
    vulnerable_sigs = []
    vulnerable_hashes = []
    
    # Create mapping from index to record
    record_map = {r['index']: r for r in attacker_records}
    
    for idx in candidates[:min(20, len(candidates))]:  # Use at most 20 signatures
        rec = record_map[idx]
        vulnerable_sigs.append((rec['r'], rec['s']))
        vulnerable_hashes.append(rec['H_m'])
    
    print(f"Using {len(vulnerable_sigs)} signatures for lattice attack")
    
    # Step 4: Prepare lattice attack data
    print("\n4. Preparing lattice attack data...")
    with open('attacker_view.json', 'r') as f:
        data = json.load(f)
        y = int(data['meta']['y'])
    
    attack_data = prepare_lattice_attack_data(
        digests=vulnerable_hashes,
        signatures=vulnerable_sigs,
        modulo=q,
        bits=bits
    )
    
    if attack_data is None:
        print("Failed to prepare lattice attack data")
        return False, 0
    
    # Step 5: Save Sage script for lattice attack
    sage_script = save_lattice_data_for_sage(attack_data)
    
    print("\n" + "="*50)
    print("ATTACK PREPARATION COMPLETE!")
    print("="*50)
    
    # Step 6: Run the Sage script
    recovered_key = run_sage_script(sage_script)
    
    if recovered_key is None:
        print("\nFailed to recover key from lattice attack")
        return False, 0
    
    return True, recovered_key


def verify_private_key(x_candidate, p, q, g, y):
    """Verify if candidate private key matches public key"""
    x_candidate = int(x_candidate)
    p = int(p)
    g = int(g)
    y = int(y)
    
    y_computed = pow(g, x_candidate, p)
    
    return y_computed == y


def get_p_q_y(filename="attacker_view.json"):
    with open(filename, "r") as f:
        data = json.load(f)

    meta = data.get("meta", {})
    p = meta.get("p")
    q = meta.get("q")
    g = meta.get("g")
    y = meta.get("y")

    return p, q, g, y


############################################
# Main Execution
############################################

def main():
    parser = argparse.ArgumentParser(description='DSA Timing + Lattice Attack')
    parser.add_argument('--bits', type=int, default=8, 
                       help='Number of assumed leaked bits (default: 8)')
    parser.add_argument('--signatures', type=int, default=200,
                       help='Number of signatures to generate')
    parser.add_argument('--seed', type=int, default=56,
                       help='Random seed (default: 56)')
    parser.add_argument('--key-size', type=int, default=1024,
                       help='DSA key size (default: 1024)')
    parser.add_argument('--base', type=float, default=100.0,
                       help='Base timing cost (default: 100.0)')
    parser.add_argument('--alpha', type=float, default=0.6,
                       help='Cost per processed bit (default: 0.6)')
    parser.add_argument('--beta', type=float, default=1.1,
                       help='Extra cost per "1" bit (default: 1.1)')
    parser.add_argument('--sigma', type=float, default=0.5,
                       help='Timing noise standard deviation (default: 0.5)')
    
    args = parser.parse_args()
    
    # Prepare for full lattice attack
    success, recovered_key = execute_complete_attack(
        bits=args.bits
    )
    
    if not success or recovered_key == 0:
        print("\n" + "="*50)
        print("ATTACK FAILED - Could not recover private key")
        print("="*50)
        return
    
    print("\n" + "="*50)
    print(f"RECOVERED KEY: {recovered_key}")
    print("="*50)
    
    # Verify the recovered key
    print("\n6. Verifying recovered private key...")
    p, q, g, y = get_p_q_y("attacker_view.json")
    
    is_valid = verify_private_key(recovered_key, p, q, g, y)
    
    print("\n" + "="*50)
    if is_valid:
        print("✓ SUCCESS! The recovered private key is VALID!")
        print(f"✓ Verified: g^x mod p = y")
    else:
        print("✗ FAILURE! The recovered private key is INVALID!")
        print(f"✗ Verification failed: g^x mod p ≠ y")
    print("="*50)


if __name__ == "__main__":
    main()