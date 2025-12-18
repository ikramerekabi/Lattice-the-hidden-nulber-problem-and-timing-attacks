#!/usr/bin/env python3
import argparse
import json
import random
import numpy as np
from sklearn.cluster import KMeans
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

############################################
# Global Parameters
############################################
KEYSIZE = 1024
N = 100  # number of signatures
F_SMALL = 0.3  # fraction of small nonces
B_SMALL = 16   # bitlength for small nonces
SEED = 56

BASE = 100.0
ALPHA = 0.6   # one cost per processed bit (loop overhead)
BETA  = 1.1   # extra cost per '1' (multiply)
SIGMA = 0.5   # timing noise

############################################
# DSA Implementation and Timing Side-Channel
############################################

def popcount(n):
    return n.bit_count()

# choose k, a random integer in the interval {1, q-1}
def choose_unbiased_k(q, rng): # not yet used 
    return rng.randint(1, q-1)

# b is always chosen such that 2^b ≪ q, hence we safely sample k ∈ [1, 2^b−1]
def choose_small_k(b, rng):
    return rng.randint(1, 2**b - 1)

def choose_big_k(b, q, rng):
    return rng.randint(2**b, q-1)

def get_k(rng, f_small, b_small, q):
    is_small = (rng.random() < f_small)
    if is_small:
        k = choose_small_k(b_small, rng)
    else:
        k = choose_big_k(b_small, q, rng)
    return k, is_small

def generate_dsa_params(key_size):
    key = DSA.generate(key_size)
    return key.p, key.q, key.g, key.x, key.y

def message_hashing(message):
    hash_obj = SHA256.new(message)
    H_m = int.from_bytes(hash_obj.digest(), byteorder='big')
    return H_m

def sign(H_m, k, x, p, q, g):
    r = pow(g, k, p) % q # r = (g^k mod p) mod q
    s = (pow(k, -1, q) * (H_m + x * r)) % q # s = k^-1 (H(m) + x*r) mod q
    return r, s

def time_leaking_function(k): # using a square-and-multiply approach
    t = BASE + ALPHA * k.bit_length() + BETA * popcount(k)
    t += random.gauss(0, SIGMA)
    return t

def generate_dataset(seed=SEED, n=N, f_small=F_SMALL, b_small=B_SMALL, key_size=KEYSIZE):
    rng = random.Random(seed)
    p, q, g, x, y = generate_dsa_params(key_size)

    print("=== DSA Parameters ===")
    print(f"Public key y: {y}")
    print(f"Prime p ({p.bit_length()} bits): {p}")
    print(f"Prime q ({q.bit_length()} bits): {q}")
    print(f"Generator g: {g}")
    print(f"Private key x: {x}\n")

    records = []
    attacker_records = []
    for i in range(n):
        k, small_k = get_k(rng, f_small, b_small, q)

        message = f"Message {i}".encode()
        H_m = message_hashing(message)

        r, s = sign(H_m, k, x, p, q, g)

        rec = {
            "index": i,
            "k": k,
            "is_small": small_k,
            "k_bitlen": k.bit_length(),
            "r": r,
            "s": s,
            "H_m": H_m,
            "message": message.hex()
        }

        attack_rec = {
            "index": i,
            "time_taken": time_leaking_function(k),
            "H_m": H_m,
            "message": message.hex(),
            "r": r,
            "s": s,
        }

        records.append(rec)
        attacker_records.append(attack_rec)

    # summary
    total_small = sum(1 for r in records if r["is_small"])
    max_k_bits = max(r["k_bitlen"] for r in records)
    min_k_bits = min(r["k_bitlen"] for r in records)
    
    print("=== Dataset Summary ===")
    print(f"n = {n}, f_small = {f_small}, b_small = {b_small}, seed = {seed}")
    print(f"Small nonce count = {total_small} ({total_small/n:.2%})")
    print(f"Nonce bitlen range = {min_k_bits} .. {max_k_bits}")

    # saving the datasets
    out = {
        "meta": {
            "n": n,
            "f_small": f_small,
            "b_small": b_small,
            "seed": seed,
            "key_size": key_size,
            "p": str(p),
            "q": str(q),
            "g": str(g),
            "y": str(y),
            "x": str(x)
        },
        "records": records
    }
    
    with open("analysis.json", "w") as fh:
        json.dump(out, fh, indent=2)
    print("Saved full dataset to analysis.json")

    attacker_out = {
        "meta": {
            "n": n,
            "p": str(p),
            "q": str(q),
            "g": str(g),
            "y": str(y),
        },
        "records": attacker_records
    }
    
    with open("attacker_view.json", "w") as fh:
        json.dump(attacker_out, fh, indent=2)
    print("Saved attacker view to attacker_view.json")

    return records, q, x

############################################
# Timing Analysis for Candidate Selection
############################################

# reads the JSON file and selects candidate indices based on time_taken.
def read_and_select_candidates(file_path, method='kmeans', value=25):
    with open(file_path, 'r') as f:
        data = json.load(f)
    
    records = data['records']
    q = data['meta']['q']
    
    # extracting times and indices
    times = np.array([r['time_taken'] for r in records])
    indices = np.array([r['index'] for r in records])
    
    print(f"Timing statistics: min={times.min():.2f}, max={times.max():.2f}, mean={times.mean():.2f}")

    # selecting candidates based on method
    if method == 'threshold':
        candidates = indices[times < value].tolist()
        print(f"Using threshold method with cutoff {value}...\n")
    elif method == 'percentile':
        cutoff = np.percentile(times, value)
        candidates = indices[times < cutoff].tolist()
        print(f"Using percentile method (cutoff={cutoff:.2f})...\n")
    elif method == 'kmeans':
        kmeans = KMeans(n_clusters=2, random_state=42).fit(times.reshape(-1,1))
        labels = kmeans.labels_
        fast_label = np.argmin(kmeans.cluster_centers_)
        candidates = indices[labels == fast_label].tolist()
        print(f"Using kmeans method...")
    else:
        raise ValueError("Unsupported method. Use 'threshold', 'percentile', or 'kmeans'.")
    
    print(f"Found {len(candidates)} fast signatures!")
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

############################################
# Complete Attack Pipeline
############################################

def execute_complete_attack(bits=8, timing_method='kmeans'):
    """Complete attack pipeline: timing analysis -> lattice attack preparation"""

    
    # Step 1: Generate dataset
    print("1. Generating DSA signatures...")
    records, q, true_private_key = generate_dataset()
    true_private_key = int(true_private_key)
    
    # Step 2: Timing analysis to find vulnerable signatures
    print("\n2. Performing timing analysis...")
    candidates, attacker_records, q = read_and_select_candidates(
        'attacker_view.json', 
        method=timing_method, 
        value=25
    )
    
    
    if len(candidates) < 3:
        print("Not enough vulnerable signatures found. Try increasing F_SMALL or N.")
        return False, 0, true_private_key
    
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
        return False, 0, true_private_key
    
    # Step 5: Save Sage script for lattice attack
    sage_script = save_lattice_data_for_sage(attack_data)
    
    print("\n" + "="*13)
    print("ATTACK READY!")
    print("="*13)
    
    return True, 0, true_private_key


############################################
# Main Execution
############################################

def main():
    parser = argparse.ArgumentParser(description='DSA Timing + Lattice Attack')
    parser.add_argument('--bits', type=int, default=8, 
                       help='Number of known MSB bits (default: 8)')
    parser.add_argument('--timing-method', choices=['kmeans', 'percentile', 'threshold'], 
                       default='kmeans', help='Timing analysis method')
    parser.add_argument('--signatures', type=int, default=200,
                       help='Number of signatures to generate')
    
    args = parser.parse_args()
    
    # Set parameters
    global N
    N = args.signatures
    

    # Prepare for full lattice attack
    success, recovered_key, true_key = execute_complete_attack(
        bits=args.bits,
        timing_method=args.timing_method
    )
    
    print(f"True private key (for verification): {true_key}")

if __name__ == "__main__":
    main()