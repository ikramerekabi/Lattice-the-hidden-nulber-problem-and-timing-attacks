#!/usr/bin/env python3
import argparse
import json
import random
import os
from Crypto.PublicKey import DSA
from Crypto.Hash import SHA256

############################################
# DSA Implementation and Timing Side-Channel
############################################

def popcount(n):
    return n.bit_count()

# b is always chosen such that 2^b ≪ q, hence we safely sample k ∈ [1, 2^b−1]
def get_small_k(b, rng):
    return rng.randint(1, 2**b - 1)

def generate_or_load_dsa_params(key_size, keyfile="dsa_key.pem"):
    if os.path.exists(keyfile):
        key = DSA.import_key(open(keyfile, "rb").read())
    else:
        key = DSA.generate(key_size)
        with open(keyfile, "wb") as f:
            f.write(key.export_key())
    return key.p, key.q, key.g, key.x, key.y

def message_hashing(message):
    hash_obj = SHA256.new(message)
    H_m = int.from_bytes(hash_obj.digest(), byteorder='big')
    return H_m

def sign(H_m, k, x, p, q, g):
    r = pow(g, k, p) % q
    s = (pow(k, -1, q) * (H_m + x * r)) % q
    return r, s

def time_leaking_function(k, noise_rng, BASE=100.0, ALPHA=0.6, BETA=1.1, SIGMA=0.5):
    t = BASE + ALPHA * k.bit_length() + BETA * popcount(k)
    t += noise_rng.gauss(0, SIGMA)
    return t

def generate_victim_dataset(n=200, seed=3, key_size=1024, BASE=100.0,
                            ALPHA=0.6, BETA=1.1, SIGMA=0.5, small_bits=16):
    rng = random.Random(seed)
    noise_rng = random.Random(seed)
    p, q, g, x, y = generate_or_load_dsa_params(key_size)

    print("=== DSA Parameters ===")
    print(f"Public key y: {y}")
    print(f"Prime p ({p.bit_length()} bits): {p}")
    print(f"Prime q ({q.bit_length()} bits): {q}")
    print(f"Generator g: {g}")
    print(f"Private key x: {x}\n")

    records = []
    attacker_records = []
    for i in range(n):
        k = get_small_k(small_bits, rng)
        message = f"Message {i}".encode()
        H_m = message_hashing(message)

        r, s = sign(H_m, k, x, p, q, g)

        rec = {
            "index": i,
            "k": k,
            "k_bitlen": k.bit_length(),
            "r": r,
            "s": s,
            "H_m": H_m,
            "message": message.hex()
        }

        attack_rec = {
            "index": i,
            "time_taken": time_leaking_function(k, noise_rng,BASE, ALPHA, BETA, SIGMA),
            "H_m": H_m,
            "message": message.hex(),
            "r": r,
            "s": s,
        }

        records.append(rec)
        attacker_records.append(attack_rec)

    # summary
    print("=== Dataset Summary ===")
    print(f"n = {n}, seed = {seed}")

    bitlen_stats = [r["k_bitlen"] for r in records]
    print(f"Nonce bitlength range = {min(bitlen_stats)} .. {max(bitlen_stats)}")
    print(f"Average nonce bitlength = {sum(bitlen_stats)/len(bitlen_stats):.2f}")

    # saving the datasets
    out = {
        "meta": {
            "n": n,
            "seed": seed,
            "key_size": key_size,
            "BASE": BASE,
            "ALPHA": ALPHA,
            "BETA": BETA,
            "SIGMA": SIGMA,
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

def main():
    parser = argparse.ArgumentParser(description='Victim: DSA signing with timing leakage')
    parser.add_argument('--signatures', type=int, default=20,
                       help='Number of signatures to generate')
    parser.add_argument('--seed', type=int, default=3,
                       help='Random seed (default: 3)')
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
    parser.add_argument('--small-bits', type=int, default=16,
                        help='Number of bits for small nonces in HNP demo')

    
    args = parser.parse_args()
    
    generate_victim_dataset(
        n=args.signatures,
        seed=args.seed,
        key_size=args.key_size,
        BASE=args.base,
        ALPHA=args.alpha,
        BETA=args.beta,
        SIGMA=args.sigma,
        small_bits=args.small_bits
    )

if __name__ == "__main__":
    main()