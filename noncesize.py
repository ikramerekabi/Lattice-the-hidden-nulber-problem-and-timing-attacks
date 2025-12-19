#!/usr/bin/env python3
"""
Nonce Size Analysis for DSA Timing Attack
Measures how short nonces need to be for timing leakage to be exploitable
"""

import argparse
import json
import subprocess
import time
import numpy as np
import matplotlib.pyplot as plt
import math
from typing import Dict, List, Tuple
import os

def clean_output_files():
    """Clean up output files between runs"""
    files_to_remove = ['analysis.json', 'attacker_view.json', 'lattice_data.sage']
    for file in files_to_remove:
        try:
            if os.path.exists(file):
                os.remove(file)
        except:
            pass

def run_victim(nonces_bits: int, num_signatures: int = 200, seed: int = 42) -> bool:
    """Run victim.py to generate signatures with given nonce size"""
    cmd = [
        'python', 'victim.py',
        '--signatures', str(num_signatures),
        '--seed', str(seed),
        '--small-bits', str(nonces_bits)
    ]
    
    print(f"  Running victim with nonce bits = {nonces_bits}...")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            print(f"  Error running victim: {result.stderr}")
            return False
        return True
    except subprocess.TimeoutExpired:
        print("  Timeout running victim")
        return False
    except Exception as e:
        print(f"  Exception running victim: {e}")
        return False

def run_attacker(bits: int = 8) -> Tuple[bool, int]:
    """Run attacker.py and extract results"""
    cmd = [
        'python', 'attacker.py',
        '--bits', str(bits)
    ]
    
    print(f"  Running attacker with known bits = {bits}...")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        # Check for success
        success = False
        recovered_key = 0
        
        # Look for success/failure patterns in output
        if "SUCCESS! The recovered private key is VALID!" in result.stdout:
            success = True
            # Extract the recovered key
            for line in result.stdout.split('\n'):
                if "RECOVERED KEY:" in line:
                    try:
                        recovered_key = int(line.split(':')[1].strip())
                        break
                    except:
                        pass
        elif "ATTACK FAILED" in result.stdout or "KEY_RESULT = 0" in result.stdout:
            success = False
        
        # Also check for Sage-specific failures
        if "Sage is not installed" in result.stdout:
            print("  ERROR: SageMath is not installed or not in PATH")
            success = False
        
        return success, recovered_key
    except subprocess.TimeoutExpired:
        print("  Timeout running attacker")
        return False, 0
    except Exception as e:
        print(f"  Exception running attacker: {e}")
        return False, 0

def get_actual_key() -> int:
    """Extract actual private key from analysis.json"""
    try:
        with open('analysis.json', 'r') as f:
            data = json.load(f)
            return int(data['meta']['x'])
    except:
        return 0

def verify_recovered_key(recovered_key: int) -> bool:
    """Verify if recovered key matches actual key"""
    if recovered_key == 0:
        return False
    
    actual_key = get_actual_key()
    if actual_key == 0:
        return False
    
    return recovered_key == actual_key

def run_experiment(nonces_bits: int, num_signatures: int = 200, 
                   known_bits: int = 8, trials: int = 10) -> float:
    """
    Run multiple trials for a given nonce size
    
    Returns: success rate (0.0 to 1.0)
    """
    print(f"\n{'='*60}")
    print(f"Testing nonce bits = {nonces_bits}")
    print(f"Number of signatures per trial: {num_signatures}")
    print(f"Number of trials: {trials}")
    print(f"{'='*60}")
    
    successes = 0
    total_time = 0
    
    for trial in range(trials):
        print(f"\n  Trial {trial + 1}/{trials}")
        
        # Clean up previous files
        clean_output_files()
        
        # Run victim with different seed for each trial
        start_time = time.time()
        
        if not run_victim(nonces_bits, num_signatures, seed=42 + trial):
            print("  Failed to generate signatures, skipping trial")
            continue
        
        # Run attacker
        success, recovered_key = run_attacker(known_bits)
        
        # Verify the key if recovered
        if success and recovered_key > 0:
            if verify_recovered_key(recovered_key):
                successes += 1
                print(f"  ✓ Trial {trial + 1}: SUCCESS")
            else:
                print(f"  ✗ Trial {trial + 1}: WRONG KEY")
        else:
            print(f"  ✗ Trial {trial + 1}: FAILED")
        
        trial_time = time.time() - start_time
        total_time += trial_time
        print(f"  Time: {trial_time:.2f} seconds")
    
    success_rate = successes / trials if trials > 0 else 0
    avg_time = total_time / trials if trials > 0 else 0
    
    print(f"\n  Summary for nonce bits = {nonces_bits}:")
    print(f"    Successes: {successes}/{trials}")
    print(f"    Success rate: {success_rate:.2%}")
    print(f"    Average time per trial: {avg_time:.2f} seconds")
    
    return success_rate

def plot_results(results: Dict[int, float], output_file: str = "nonce_size_analysis.png"):
    """Plot success rate vs nonce bit length"""
    
    # Sort by nonce bits
    bits_list = sorted(results.keys())
    success_rates = [results[bits] for bits in bits_list]
    
    # Create figure
    plt.figure(figsize=(14, 8))
    
    # Create a single plot (no subplots)
    plt.figure(figsize=(12, 7))
    
    # Plot success rate as individual markers (no line)
    colors = []
    sizes = []
    for rate in success_rates:
        if rate >= 0.8:
            colors.append('green')
            sizes.append(80)
        elif rate >= 0.5:
            colors.append('orange')
            sizes.append(60)
        else:
            colors.append('red')
            sizes.append(40)
    
    # Scatter plot with individual markers
    for i, (bits, rate) in enumerate(zip(bits_list, success_rates)):
        plt.scatter(bits, rate, s=sizes[i], c=colors[i], alpha=0.7, 
                   edgecolors='black', linewidth=1, zorder=5)
        
        # Annotate each point with the value
        plt.annotate(f'{rate:.0%}', 
                    xy=(bits, rate), 
                    xytext=(0, 10),
                    textcoords='offset points',
                    ha='center',
                    fontsize=9,
                    fontweight='bold',
                    bbox=dict(boxstyle="round,pad=0.2", facecolor="white", alpha=0.8))
    
    # Add 50% threshold line only
    plt.axhline(y=0.5, color='red', linestyle='--', alpha=0.7, linewidth=1.5, 
               label='50% Success Threshold')
    
    # Labels and title
    plt.xlabel('Nonce Bit Length', fontsize=14)
    plt.ylabel('Attack Success Rate', fontsize=14)
    plt.title('DSA Timing Attack: Success Rate vs Nonce Size', 
             fontsize=16, fontweight='bold', pad=20)
    
    # Grid and ticks
    plt.grid(True, alpha=0.3, linestyle='--')
    plt.xticks(bits_list)
    plt.yticks(np.arange(0, 1.1, 0.1))
    
    # Set axis limits with some padding
    plt.xlim(min(bits_list) - 1, max(bits_list) + 1)
    plt.ylim(-0.05, 1.05)
    
    # Legend
    plt.legend(fontsize=11, loc='upper right')
    
    # Add color legend for markers
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor='green', alpha=0.7, edgecolor='black', 
              label='High Success (≥80%)'),
        Patch(facecolor='orange', alpha=0.7, edgecolor='black', 
              label='Moderate Success (≥50%)'),
        Patch(facecolor='red', alpha=0.7, edgecolor='black', 
              label='Low Success (<50%)')
    ]
    plt.legend(handles=legend_elements, fontsize=11, loc='upper right')
    
    # Adjust layout and save
    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"\nPlot saved to {output_file}")
    
    # Show plot
    plt.show()

def generate_analysis_text(results: Dict[int, float]) -> str:
    """Generate analysis text for the plot"""
    if not results:
        return "No results available"
    
    sorted_results = sorted(results.items())
    bits_list = [b for b, _ in sorted_results]
    rates = [r for _, r in sorted_results]
    
    # Find MAXIMUM bits for each threshold (not minimum)
    high_success_bits = [b for b, r in sorted_results if r >= 0.8]
    moderate_success_bits = [b for b, r in sorted_results if r >= 0.5]
    low_success_bits = [b for b, r in sorted_results if r < 0.5]
    
    analysis = "ANALYSIS\n"
    analysis += "=" * 30 + "\n"
    
    if high_success_bits:
        max_high = max(high_success_bits)
        analysis += f"High Success (≥80%):\n"
        analysis += f"  Works up to ℓ = {max_high} bits\n"
        analysis += f"  Max nonce: 2^{max_high} - 1\n"
        analysis += f"  = {2**max_high - 1:,}\n\n"
    
    if moderate_success_bits:
        max_mod = max(moderate_success_bits)
        min_mod = min(moderate_success_bits)
        analysis += f"Moderate Success (≥50%):\n"
        analysis += f"  Works up to ℓ = {max_mod} bits\n"
        analysis += f"  Max nonce: 2^{max_mod} - 1\n"
        analysis += f"  = {2**max_mod - 1:,}\n\n"
    
    if low_success_bits:
        min_low = min(low_success_bits)
        analysis += f"Low Success (<50%):\n"
        analysis += f"  Starts at ℓ = {min_low} bits\n"
        analysis += f"  Min nonce: 2^{min_low} - 1\n"
        analysis += f"  = {2**min_low - 1:,}\n\n"
    
    # Find critical threshold (where success drops below 50%)
    critical_threshold = None
    for i in range(len(bits_list) - 1):
        if rates[i] >= 0.5 and rates[i+1] < 0.5:
            critical_threshold = bits_list[i+1]
            break
    
    if critical_threshold:
        analysis += f"Critical Threshold:\n"
        analysis += f"  Attack fails at ℓ ≥ {critical_threshold} bits\n"
        analysis += f"  Nonce ≥ 2^{critical_threshold} - 1\n"
        analysis += f"  = {2**critical_threshold - 1:,}"
    
    return analysis

def find_threshold(results: Dict[int, float], target_rate: float) -> str:
    """Find the maximum nonce bit length where success rate is ≥ target_rate"""
    if not results:
        return "N/A"
    
    # Find all bits where success rate is ≥ target_rate
    successful_bits = [bits for bits, rate in results.items() if rate >= target_rate]
    
    if not successful_bits:
        return "None"
    
    # Return the MAXIMUM (not minimum) successful bit length
    return str(max(successful_bits))

def save_results_to_csv(results: Dict[int, float], filename: str = "nonce_size_results.csv"):
    """Save results to CSV file"""
    with open(filename, 'w') as f:
        f.write("nonce_bits,success_rate,nonce_max_value,success_category\n")
        for bits in sorted(results.keys()):
            max_value = 2**bits - 1
            rate = results[bits]
            if rate >= 0.8:
                category = "High"
            elif rate >= 0.5:
                category = "Moderate"
            else:
                category = "Low"
            f.write(f"{bits},{rate:.4f},{max_value},{category}\n")
    print(f"\nResults saved to {filename}")

def check_dependencies():
    """Check if required dependencies are installed"""
    required_packages = ['numpy', 'matplotlib']
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print("ERROR: Missing required packages:")
        for package in missing_packages:
            print(f"  - {package}")
        print("\nPlease install with: pip install", " ".join(missing_packages))
        return False
    
    # Check if SageMath is available
    try:
        result = subprocess.run(['sage', '--version'], 
                              capture_output=True, 
                              text=True, 
                              timeout=5)
        if result.returncode != 0:
            print("WARNING: SageMath is not installed or not in PATH")
            print("The lattice attack part will fail without SageMath.")
            user_input = input("Continue anyway? (y/n): ")
            if user_input.lower() != 'y':
                return False
    except:
        print("WARNING: SageMath is not installed or not in PATH")
        print("The lattice attack part will fail without SageMath.")
        user_input = input("Continue anyway? (y/n): ")
        if user_input.lower() != 'y':
            return False
    
    return True

def generate_continuous_sequence(min_bits: int, max_bits: int, step: int = 1) -> List[int]:
    """
    Generate a continuous sequence of nonce bit lengths
    
    Args:
        min_bits: Minimum bit length
        max_bits: Maximum bit length
        step: Step size (default: test every integer)
    
    Returns:
        List of bit lengths to test
    """
    if step <= 0:
        step = 1
    
    sequence = list(range(min_bits, max_bits + 1, step))
    
    # Ensure max_bits is included
    if sequence and sequence[-1] != max_bits:
        sequence.append(max_bits)
    
    return sorted(set(sequence))

def generate_power_sequence(min_bits: int, max_bits: int, base: int = 2) -> List[int]:
    """
    Generate sequence based on powers
    
    Args:
        min_bits: Minimum bit length
        max_bits: Maximum bit length
        base: Base for exponential growth (2 for powers of 2)
    
    Returns:
        List of bit lengths to test
    """
    sequence = []
    
    # Generate powers
    power = 0
    while base**power <= max_bits:
        bits = base**power
        if bits >= min_bits:
            sequence.append(bits)
        power += 1
    
    # Add min and max if not included
    if min_bits not in sequence:
        sequence.insert(0, min_bits)
    if max_bits not in sequence:
        sequence.append(max_bits)
    
    return sorted(set(sequence))

def main():
    parser = argparse.ArgumentParser(
        description='Analyze DSA timing attack success rate vs nonce size',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example usage:
  # Test every integer from 4 to 32 bits
  %(prog)s --min-bits 4 --max-bits 32 --continuous
  
  # Test powers of 2
  %(prog)s --min-bits 4 --max-bits 128 --powers-of-2
  
  # Test with custom step
  %(prog)s --min-bits 4 --max-bits 64 --step 4
        
This answers: "How short does the nonce need to be for timing leakage to be exploitable?"
        """
    )
    
    # Testing modes
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('--continuous', action='store_true',
                          help='Test every integer bit length (continuous data)')
    mode_group.add_argument('--powers-of-2', action='store_true',
                          help='Test powers of 2')
    mode_group.add_argument('--bits', nargs='+', type=int,
                          help='List of specific nonce bit lengths to test')
    
    # Range parameters
    parser.add_argument('--min-bits', type=int, default=4,
                       help='Minimum nonce bit length')
    parser.add_argument('--max-bits', type=int, default=32,
                       help='Maximum nonce bit length')
    parser.add_argument('--step', type=int, default=1,
                       help='Step size for continuous testing')
    parser.add_argument('--power-base', type=int, default=2,
                       help='Base for power sequence (default: 2)')
    
    # Experiment parameters
    parser.add_argument('--trials', type=int, default=3,
                       help='Number of trials per nonce size')
    parser.add_argument('--signatures', type=int, default=200,
                       help='Number of signatures per trial')
    parser.add_argument('--known-bits', type=int, default=8,
                       help='Number of known MSB bits for lattice attack')
    
    # Output options
    parser.add_argument('--output-plot', type=str, default='nonce_size_analysis.png',
                       help='Output plot filename')
    parser.add_argument('--output-csv', type=str, default='nonce_size_results.csv',
                       help='Output CSV filename')
    parser.add_argument('--skip-plot', action='store_true',
                       help='Skip plotting (just run experiments)')
    parser.add_argument('--quick', action='store_true',
                       help='Run quick test with fewer trials')
    
    args = parser.parse_args()
    
    # Adjust parameters for quick mode
    if args.quick:
        args.trials = max(1, args.trials // 2)
        args.signatures = min(args.signatures, 100)
        if args.continuous and args.step < 2:
            args.step = 2
    
    # Check dependencies
    if not check_dependencies():
        return
    
    # Determine which nonce bits to test
    if args.bits:
        # Use specific bits list
        nonce_bits_list = sorted(set(args.bits))
        mode = "specific bits"
    elif args.powers_of_2:
        # Generate powers sequence
        nonce_bits_list = generate_power_sequence(
            min_bits=args.min_bits,
            max_bits=args.max_bits,
            base=args.power_base
        )
        mode = f"powers of {args.power_base}"
    elif args.continuous:
        # Generate continuous sequence
        nonce_bits_list = generate_continuous_sequence(
            min_bits=args.min_bits,
            max_bits=args.max_bits,
            step=args.step
        )
        mode = f"continuous (step={args.step})"
    else:
        # Default: linear progression
        nonce_bits_list = generate_continuous_sequence(
            min_bits=args.min_bits,
            max_bits=args.max_bits,
            step=args.step
        )
        mode = f"linear (step={args.step})"
    
    # Check if we're testing too many points
    num_points = len(nonce_bits_list)
    estimated_time = num_points * args.trials * 5  # Rough estimate: 5 seconds per trial
    
    if num_points > 20 and not args.quick:
        print(f"\n⚠️  WARNING: Testing {num_points} points with {args.trials} trials each.")
        print(f"Estimated time: ~{estimated_time//60} minutes")
        print("Consider using --quick flag or reducing the range.")
        user_input = input("Continue? (y/n): ")
        if user_input.lower() != 'y':
            return
    
    print(f"{'='*70}")
    print("DSA TIMING ATTACK - NONCE SIZE ANALYSIS")
    print(f"{'='*70}")
    print(f"Testing mode: {mode}")
    print(f"Number of test points: {num_points}")
    print(f"Nonce bit lengths: {nonce_bits_list}")
    print(f"Trials per size: {args.trials}")
    print(f"Signatures per trial: {args.signatures}")
    print(f"Known bits for lattice attack: {args.known_bits}")
    print(f"{'='*70}")
    
    # Run experiments
    results = {}
    experiment_times = []
    
    for i, nonce_bits in enumerate(nonce_bits_list):
        print(f"\n[{i+1}/{num_points}] ", end="")
        start_time = time.time()
        success_rate = run_experiment(
            nonces_bits=nonce_bits,
            num_signatures=args.signatures,
            known_bits=args.known_bits,
            trials=args.trials
        )
        results[nonce_bits] = success_rate
        experiment_times.append(time.time() - start_time)
        
        # Estimate remaining time
        if i < num_points - 1:
            avg_time = sum(experiment_times) / len(experiment_times)
            remaining = avg_time * (num_points - i - 1)
            print(f"  Estimated time remaining: {remaining//60:.0f}m {remaining%60:.0f}s")
    
    # Calculate statistics
    total_time = sum(experiment_times)
    avg_time_per_point = total_time / num_points if num_points > 0 else 0
    
    # Save results
    save_results_to_csv(results, args.output_csv)
    
    # Plot results
    if not args.skip_plot:
        plot_results(results, args.output_plot)
    
    # Print comprehensive summary
    print(f"\n{'='*70}")
    print("EXPERIMENT SUMMARY")
    print(f"{'='*70}")
    print(f"Total experiment time: {total_time:.1f} seconds ({total_time/60:.1f} minutes)")
    print(f"Average time per nonce size: {avg_time_per_point:.1f} seconds")
    
    # Print results table
    print(f"\n{'Nonce Bits':<12} {'Max Nonce Value':<20} {'Success Rate':<15} {'Category':<12}")
    print(f"{'-'*65}")
    
    for bits in sorted(results.keys()):
        max_nonce = 2**bits - 1
        rate = results[bits]
        if rate >= 0.8:
            category = "HIGH"
        elif rate >= 0.5:
            category = "MODERATE"
        else:
            category = "LOW"
        
        # Format max_nonce for readability
        if max_nonce > 1_000_000:
            max_nonce_str = f"{max_nonce:.2e}"
        else:
            max_nonce_str = f"{max_nonce:,}"
        
        print(f"{bits:<12} {max_nonce_str:<20} {rate:<15.1%} {category:<12}")
    
    # Analysis section with CORRECTED thresholds (using MAXIMUM values)
    print(f"\n{'='*70}")
    print("ANALYSIS - CORRECTED THRESHOLDS")
    print(f"{'='*70}")
    
    # Find MAXIMUM bits for each threshold
    sorted_results = sorted(results.items())
    high_success = [(bits, rate) for bits, rate in sorted_results if rate >= 0.8]
    moderate_success = [(bits, rate) for bits, rate in sorted_results if rate >= 0.5]
    low_success = [(bits, rate) for bits, rate in sorted_results if rate < 0.5]
    
    if high_success:
        max_high_bits = max([bits for bits, _ in high_success])
        max_high_rate = results[max_high_bits]
        print(f"✓ HIGH SUCCESS (≥80%):")
        print(f"  Maximum nonce size: {max_high_bits} bits")
        print(f"  Success rate at {max_high_bits} bits: {max_high_rate:.1%}")
        print(f"  Corresponding to nonces ≤ 2^{max_high_bits} - 1 = {2**max_high_bits - 1:,}")
        print()
    
    if moderate_success:
        max_mod_bits = max([bits for bits, _ in moderate_success])
        max_mod_rate = results[max_mod_bits]
        print(f"✓ MODERATE SUCCESS (≥50%):")
        print(f"  Maximum nonce size: {max_mod_bits} bits")
        print(f"  Success rate at {max_mod_bits} bits: {max_mod_rate:.1%}")
        print(f"  Corresponding to nonces ≤ 2^{max_mod_bits} - 1 = {2**max_mod_bits - 1:,}")
        print()
    
    if low_success:
        min_low_bits = min([bits for bits, _ in low_success])
        min_low_rate = results[min_low_bits]
        print(f"✗ LOW SUCCESS (<50%):")
        print(f"  Starts at nonce size: {min_low_bits} bits")
        print(f"  Success rate at {min_low_bits} bits: {min_low_rate:.1%}")
        print(f"  Corresponding to nonces ≥ 2^{min_low_bits} - 1 = {2**min_low_bits - 1:,}")
        print()
    
    # Find critical threshold (where success drops below 50%)
    critical_threshold = None
    for i in range(len(sorted_results) - 1):
        bits1, rate1 = sorted_results[i]
        bits2, rate2 = sorted_results[i + 1]
        
        if rate1 >= 0.5 and rate2 < 0.5:
            critical_threshold = bits2  # The point where it drops below 50%
            print(f"⚠️  CRITICAL THRESHOLD:")
            print(f"  Attack effectiveness drops at: {critical_threshold} bits")
            print(f"  Success: {rate1:.1%} at {bits1} bits → {rate2:.1%} at {bits2} bits")
            print(f"  Nonce size: 2^{critical_threshold} - 1 = {2**critical_threshold - 1:,}")
            break
    
    # Final answer
    print(f"\n{'='*70}")
    print("RESEARCH QUESTION ANSWER")
    print(f"{'='*70}")
    
    if moderate_success:
        max_successful_bits = max([bits for bits, _ in moderate_success])
        print(f"Q: How short does the nonce need to be for timing leakage to be exploitable?")
        print(f"A: For consistent exploitation (≥50% success rate):")
        print(f"   Nonces must be ≤ {max_successful_bits} bits")
        print(f"   (Maximum value: 2^{max_successful_bits} - 1 = {2**max_successful_bits - 1:,})")
        print(f"\n   With {args.signatures} signatures and {args.trials} trials,")
        print(f"   the attack works reliably up to this nonce size.")
    else:
        print("A: The attack failed to achieve ≥50% success for any tested nonce size.")
        print("   Timing leakage alone may not be sufficient with these parameters.")
    
    print(f"{'='*70}")

if __name__ == "__main__":
    main()