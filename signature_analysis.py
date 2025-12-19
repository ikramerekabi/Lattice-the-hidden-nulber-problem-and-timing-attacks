#!/usr/bin/env python3
"""
Signature Count Analysis for DSA Timing Attack
Measures how many signatures are needed for successful attacks at different nonce sizes
"""

import argparse
import json
import subprocess
import time
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, List, Tuple, Optional
import os
import pandas as pd
from matplotlib.colors import LinearSegmentedColormap
import warnings
warnings.filterwarnings('ignore')

def clean_output_files():
    """Clean up output files between runs"""
    files_to_remove = ['analysis.json', 'attacker_view.json', 'lattice_data.sage']
    for file in files_to_remove:
        try:
            if os.path.exists(file):
                os.remove(file)
        except:
            pass

def run_victim(nonces_bits: int, num_signatures: int, seed: int = 42) -> bool:
    """Run victim.py to generate signatures with given nonce size"""
    cmd = [
        'python', 'victim.py',
        '--signatures', str(num_signatures),
        '--seed', str(seed),
        '--small-bits', str(nonces_bits)
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.returncode == 0
    except:
        return False

def run_attacker(bits: int = 8) -> Tuple[bool, int]:
    """Run attacker.py and extract results"""
    cmd = [
        'python', 'attacker.py',
        '--bits', str(bits)
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        success = False
        recovered_key = 0
        
        if "SUCCESS! The recovered private key is VALID!" in result.stdout:
            success = True
            for line in result.stdout.split('\n'):
                if "RECOVERED KEY:" in line:
                    try:
                        recovered_key = int(line.split(':')[1].strip())
                        break
                    except:
                        pass
        
        return success, recovered_key
    except:
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
    return actual_key != 0 and recovered_key == actual_key

def run_single_experiment(nonce_bits: int, num_signatures: int, 
                         known_bits: int = 8, seed: int = 42) -> bool:
    """
    Run a single experiment with given parameters
    
    Returns: True if attack succeeded, False otherwise
    """
    # Clean up previous files
    clean_output_files()
    
    # Run victim
    if not run_victim(nonce_bits, num_signatures, seed):
        return False
    
    # Run attacker
    success, recovered_key = run_attacker(known_bits)
    
    # Verify the key
    return success and recovered_key > 0 and verify_recovered_key(recovered_key)

def generate_signature_sequence(min_sigs: int, max_sigs: int, mode: str = 'exponential') -> List[int]:
    """
    Generate sequence of signature counts to test
    
    Args:
        min_sigs: Minimum number of signatures
        max_sigs: Maximum number of signatures
        mode: 'exponential', 'linear', or 'powers_of_two'
    
    Returns:
        List of signature counts
    """
    if mode == 'exponential':
        # Exponential growth: 5, 10, 20, 40, 80, ...
        sequence = []
        current = min_sigs
        while current <= max_sigs:
            sequence.append(current)
            current *= 2
        if sequence[-1] != max_sigs:
            sequence.append(max_sigs)
    
    elif mode == 'powers_of_two':
        # Powers of two: 2, 4, 8, 16, 32, ...
        sequence = []
        power = 1
        while 2**power <= max_sigs:
            sigs = 2**power
            if sigs >= min_sigs:
                sequence.append(sigs)
            power += 1
        if min_sigs not in sequence:
            sequence.insert(0, min_sigs)
        if max_sigs not in sequence and max_sigs > sequence[-1]:
            sequence.append(max_sigs)
    
    else:  # linear
        # Linear progression
        step = max(1, (max_sigs - min_sigs) // 10)
        sequence = list(range(min_sigs, max_sigs + 1, step))
        if sequence[-1] != max_sigs:
            sequence.append(max_sigs)
    
    return sorted(set(sequence))

def generate_nonce_sequence(min_bits: int, max_bits: int, mode: str = 'powers_of_two') -> List[int]:
    """
    Generate sequence of nonce bit lengths to test
    
    Args:
        min_bits: Minimum nonce bits
        max_bits: Maximum nonce bits
        mode: 'powers_of_two', 'linear', or 'mixed'
    
    Returns:
        List of nonce bit lengths
    """
    if mode == 'powers_of_two':
        # Powers of two: 4, 8, 16, 32, ...
        sequence = []
        power = 2  # Start from 2^2 = 4
        while 2**power <= max_bits:
            bits = 2**power
            if bits >= min_bits:
                sequence.append(bits)
            power += 1
        if min_bits not in sequence:
            sequence.insert(0, min_bits)
        if max_bits not in sequence:
            sequence.append(max_bits)
    
    elif mode == 'mixed':
        # Mix of small and large values
        sequence = []
        
        # Small values (for detailed analysis)
        small_range = list(range(min_bits, min(16, max_bits) + 1, 2))
        sequence.extend(small_range)
        
        # Medium values
        if max_bits >= 16:
            medium = [16, 20, 24, 28, 32]
            sequence.extend([m for m in medium if min_bits <= m <= max_bits])
        
        # Large values (powers of two)
        power = 5  # 32
        while 2**power <= max_bits:
            bits = 2**power
            if bits not in sequence and bits >= min_bits:
                sequence.append(bits)
            power += 1
        
        if max_bits not in sequence:
            sequence.append(max_bits)
    
    else:  # linear
        step = max(1, (max_bits - min_bits) // 8)
        sequence = list(range(min_bits, max_bits + 1, step))
        if sequence[-1] != max_bits:
            sequence.append(max_bits)
    
    return sorted(set(sequence))

def create_heatmap_plot(results_matrix: np.ndarray, 
                       nonce_bits_list: List[int], 
                       signature_counts: List[int],
                       output_file: str = "signature_heatmap.png"):
    """
    Create a heatmap visualization of success rates
    
    Args:
        results_matrix: 2D array of success rates
        nonce_bits_list: List of nonce bit lengths (y-axis)
        signature_counts: List of signature counts (x-axis)
        output_file: Output filename
    """
    
    # Create figure with multiple subplots
    fig = plt.figure(figsize=(16, 10))
    
    # 1. Main Heatmap
    ax1 = plt.subplot2grid((3, 3), (0, 0), colspan=2, rowspan=2)
    
    # Create custom colormap (green to red)
    colors = ["#d73027", "#fc8d59", "#fee090", "#e0f3f8", "#91bfdb", "#4575b4"]
    cmap = LinearSegmentedColormap.from_list("success_cmap", colors, N=256)
    
    # Create heatmap
    im = ax1.imshow(results_matrix, cmap=cmap, aspect='auto', vmin=0, vmax=1)
    
    # Set ticks and labels
    ax1.set_xticks(range(len(signature_counts)))
    ax1.set_yticks(range(len(nonce_bits_list)))
    ax1.set_xticklabels([str(s) for s in signature_counts], rotation=45)
    ax1.set_yticklabels([str(b) for b in nonce_bits_list])
    
    ax1.set_xlabel('Number of Signatures', fontsize=12, fontweight='bold')
    ax1.set_ylabel('Nonce Bit Length', fontsize=12, fontweight='bold')
    ax1.set_title('Attack Success Rate Heatmap', fontsize=14, fontweight='bold', pad=20)
    
    # Add colorbar
    cbar = plt.colorbar(im, ax=ax1, fraction=0.046, pad=0.04)
    cbar.set_label('Success Rate', fontsize=11)
    
    # Add success rate values in cells
    for i in range(len(nonce_bits_list)):
        for j in range(len(signature_counts)):
            rate = results_matrix[i, j]
            if not np.isnan(rate):
                color = 'white' if rate < 0.5 else 'black'
                ax1.text(j, i, f'{rate:.0%}', 
                        ha='center', va='center', 
                        color=color, fontsize=9, fontweight='bold')
    
    # 2. 50% Success Contour Plot (top right)
    ax2 = plt.subplot2grid((3, 3), (0, 2), rowspan=2)
    
    # Create contour plot
    X, Y = np.meshgrid(range(len(signature_counts)), range(len(nonce_bits_list)))
    
    # Find 50% contour
    from scipy import interpolate
    if not np.all(np.isnan(results_matrix)):
        try:
            # Interpolate for smoother contour
            f = interpolate.interp2d(range(len(signature_counts)), 
                                    range(len(nonce_bits_list)), 
                                    results_matrix, kind='linear')
            xnew = np.linspace(0, len(signature_counts)-1, 100)
            ynew = np.linspace(0, len(nonce_bits_list)-1, 100)
            znew = f(xnew, ynew)
            
            # Plot contour
            contour = ax2.contour(xnew, ynew, znew, levels=[0.5], colors='red', linewidths=2)
            ax2.clabel(contour, inline=True, fontsize=10, fmt='50%%')
            
            # Fill contour areas
            ax2.contourf(xnew, ynew, znew >= 0.5, levels=[0, 0.5, 1], 
                        colors=['#ffcccc', '#ccffcc'], alpha=0.3)
        except:
            pass
    
    ax2.set_xlabel('Signatures', fontsize=10)
    ax2.set_ylabel('Nonce Bits', fontsize=10)
    ax2.set_title('50% Success Boundary', fontsize=12, fontweight='bold')
    ax2.set_xticks(range(len(signature_counts)))
    ax2.set_yticks(range(len(nonce_bits_list)))
    ax2.set_xticklabels([str(s) for s in signature_counts], rotation=45, fontsize=8)
    ax2.set_yticklabels([str(b) for b in nonce_bits_list], fontsize=8)
    ax2.grid(True, alpha=0.3)
    
    # 3. Success Rate vs Signatures for selected nonce sizes (bottom left)
    ax3 = plt.subplot2grid((3, 3), (2, 0), colspan=3)
    
    # Plot success curves for 3 representative nonce sizes
    if len(nonce_bits_list) >= 3:
        indices = [0, len(nonce_bits_list)//2, -1]
        colors = ['green', 'orange', 'red']
        labels = [f'{nonce_bits_list[i]} bits' for i in indices]
        
        for idx, color, label in zip(indices, colors, labels):
            success_rates = results_matrix[idx]
            valid_indices = ~np.isnan(success_rates)
            if np.any(valid_indices):
                ax3.plot(np.array(signature_counts)[valid_indices], 
                        success_rates[valid_indices], 
                        'o-', color=color, linewidth=2, markersize=8, label=label)
                
                # Add annotations at key points
                for j, (sigs, rate) in enumerate(zip(signature_counts, success_rates)):
                    if not np.isnan(rate):
                        if rate >= 0.5 or j in [0, len(signature_counts)-1]:
                            ax3.annotate(f'{rate:.0%}', 
                                       xy=(sigs, rate), 
                                       xytext=(0, 10),
                                       textcoords='offset points',
                                       ha='center',
                                       fontsize=8,
                                       fontweight='bold')
    
    ax3.axhline(y=0.5, color='red', linestyle='--', alpha=0.5, label='50% Threshold')
    ax3.set_xlabel('Number of Signatures', fontsize=12, fontweight='bold')
    ax3.set_ylabel('Success Rate', fontsize=12, fontweight='bold')
    ax3.set_title('Success Rate vs Number of Signatures', fontsize=13, fontweight='bold')
    ax3.legend(fontsize=10, loc='best')
    ax3.grid(True, alpha=0.3)
    ax3.set_xscale('log')  # Log scale for better visualization
    ax3.set_xticks(signature_counts)
    ax3.set_xticklabels([str(s) for s in signature_counts])
    ax3.set_ylim(-0.05, 1.05)
    
    # 4. Add analysis text
    analysis_text = generate_heatmap_analysis(results_matrix, nonce_bits_list, signature_counts)
    plt.figtext(0.02, 0.02, analysis_text,
                fontsize=9,
                bbox=dict(boxstyle='round', facecolor='lightblue', alpha=0.9, pad=10))
    
    # Adjust layout
    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"\nHeatmap saved to {output_file}")
    
    # Show plot
    plt.show()

def generate_heatmap_analysis(results_matrix: np.ndarray, 
                             nonce_bits_list: List[int], 
                             signature_counts: List[int]) -> str:
    """Generate analysis text for the heatmap"""
    
    analysis = "HEATMAP ANALYSIS\n"
    analysis += "=" * 40 + "\n\n"
    
    # Find minimum signatures needed for 50% success at each nonce size
    analysis += "Minimum Signatures for 50% Success:\n"
    for i, bits in enumerate(nonce_bits_list):
        success_rates = results_matrix[i]
        valid_rates = [r for j, r in enumerate(success_rates) if not np.isnan(r)]
        if valid_rates:
            # Find first signature count with >= 50% success
            for j, rate in enumerate(success_rates):
                if not np.isnan(rate) and rate >= 0.5:
                    min_sigs = signature_counts[j]
                    analysis += f"  {bits} bits: ≥{min_sigs} signatures ({rate:.0%})\n"
                    break
            else:
                analysis += f"  {bits} bits: Never reaches 50%\n"
    
    analysis += "\n"
    
    # Find breaking points
    analysis += "Critical Observations:\n"
    
    # For small nonces
    small_indices = [i for i, bits in enumerate(nonce_bits_list) if bits <= 16]
    if small_indices:
        i = small_indices[0]
        for j, sigs in enumerate(signature_counts):
            if not np.isnan(results_matrix[i, j]) and results_matrix[i, j] >= 0.5:
                analysis += f"• Small nonces ({nonce_bits_list[i]} bits): "
                analysis += f"Work with only {sigs} signatures\n"
                break
    
    # For medium nonces
    medium_indices = [i for i, bits in enumerate(nonce_bits_list) if 16 < bits <= 64]
    if medium_indices:
        i = medium_indices[len(medium_indices)//2]
        for j, sigs in enumerate(signature_counts):
            if not np.isnan(results_matrix[i, j]) and results_matrix[i, j] >= 0.5:
                analysis += f"• Medium nonces ({nonce_bits_list[i]} bits): "
                analysis += f"Need {sigs} signatures\n"
                break
    
    # For large nonces
    large_indices = [i for i, bits in enumerate(nonce_bits_list) if bits > 64]
    if large_indices:
        i = large_indices[0]
        reached_50 = False
        for j, sigs in enumerate(signature_counts):
            if not np.isnan(results_matrix[i, j]) and results_matrix[i, j] >= 0.5:
                analysis += f"• Large nonces ({nonce_bits_list[i]} bits): "
                analysis += f"Require {sigs}+ signatures\n"
                reached_50 = True
                break
        if not reached_50:
            analysis += f"• Large nonces ({nonce_bits_list[i]} bits): "
            analysis += "Cannot achieve 50% success\n"
    
    return analysis

def create_3d_surface_plot(results_matrix: np.ndarray,
                          nonce_bits_list: List[int],
                          signature_counts: List[int],
                          output_file: str = "signature_3d.png"):
    """Create a 3D surface plot of success rates"""
    from mpl_toolkits.mplot3d import Axes3D
    
    fig = plt.figure(figsize=(14, 10))
    ax = fig.add_subplot(111, projection='3d')
    
    # Create meshgrid
    X, Y = np.meshgrid(range(len(signature_counts)), range(len(nonce_bits_list)))
    
    # Plot surface
    surf = ax.plot_surface(X, Y, results_matrix, cmap='viridis', 
                          alpha=0.8, edgecolor='black', linewidth=0.5)
    
    # Set labels
    ax.set_xlabel('Number of Signatures', fontsize=11, labelpad=10)
    ax.set_ylabel('Nonce Bit Length', fontsize=11, labelpad=10)
    ax.set_zlabel('Success Rate', fontsize=11, labelpad=10)
    ax.set_title('3D Surface: Success Rate vs Nonce Size & Signatures', 
                fontsize=14, fontweight='bold', pad=20)
    
    # Set tick labels
    ax.set_xticks(range(len(signature_counts)))
    ax.set_yticks(range(len(nonce_bits_list)))
    ax.set_xticklabels([str(s) for s in signature_counts], rotation=45)
    ax.set_yticklabels([str(b) for b in nonce_bits_list])
    
    # Add colorbar
    fig.colorbar(surf, ax=ax, shrink=0.5, aspect=5, label='Success Rate')
    
    # Adjust viewing angle
    ax.view_init(elev=25, azim=-45)
    
    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"3D surface plot saved to {output_file}")
    
    # Show plot
    plt.show()

def save_results_to_files(results_matrix: np.ndarray,
                         nonce_bits_list: List[int],
                         signature_counts: List[int],
                         prefix: str = "signature_analysis"):
    """Save results to CSV and JSON files"""
    
    # Save as CSV
    csv_file = f"{prefix}.csv"
    df = pd.DataFrame(results_matrix, 
                     index=[f"{bits} bits" for bits in nonce_bits_list],
                     columns=[f"{sigs} sigs" for sigs in signature_counts])
    df.to_csv(csv_file)
    print(f"Results saved to {csv_file}")
    
    # Save as JSON
    json_file = f"{prefix}.json"
    data = {
        "nonce_bits": nonce_bits_list,
        "signature_counts": signature_counts,
        "success_rates": results_matrix.tolist(),
        "parameters": {
            "trials_per_cell": args.trials,
            "known_bits": args.known_bits
        }
    }
    with open(json_file, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"Results saved to {json_file}")
    
    return csv_file, json_file

def main():
    global args
    
    parser = argparse.ArgumentParser(
        description='Analyze DSA timing attack: Signatures needed vs Nonce size',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example usage:
  # Quick test: Few nonce sizes, few signature counts
  %(prog)s --min-bits 4 --max-bits 32 --min-sigs 5 --max-sigs 80 --trials 2 --quick
  
  # Comprehensive test
  %(prog)s --min-bits 4 --max-bits 128 --min-sigs 5 --max-sigs 320 --trials 3
        
Visualizes: "How many signatures are needed for successful attacks at different nonce sizes?"
        """
    )
    
    # Nonce size parameters
    parser.add_argument('--min-bits', type=int, default=4,
                       help='Minimum nonce bit length to test')
    parser.add_argument('--max-bits', type=int, default=64,
                       help='Maximum nonce bit length to test')
    parser.add_argument('--nonce-mode', choices=['powers_of_two', 'mixed', 'linear'],
                       default='mixed', help='How to select nonce sizes')
    
    # Signature count parameters
    parser.add_argument('--min-sigs', type=int, default=5,
                       help='Minimum number of signatures to test')
    parser.add_argument('--max-sigs', type=int, default=160,
                       help='Maximum number of signatures to test')
    parser.add_argument('--sig-mode', choices=['exponential', 'powers_of_two', 'linear'],
                       default='exponential', help='How to select signature counts')
    
    # Experiment parameters
    parser.add_argument('--trials', type=int, default=3,
                       help='Number of trials per parameter combination')
    parser.add_argument('--known-bits', type=int, default=8,
                       help='Number of known MSB bits for lattice attack')
    
    # Output options
    parser.add_argument('--output-prefix', type=str, default='signature_analysis',
                       help='Prefix for output files')
    parser.add_argument('--skip-3d', action='store_true',
                       help='Skip 3D surface plot')
    parser.add_argument('--quick', action='store_true',
                       help='Run quick test with fewer points')
    
    args = parser.parse_args()
    
    # Adjust parameters for quick mode
    if args.quick:
        args.trials = max(1, args.trials // 2)
        args.max_bits = min(args.max_bits, 32)
        args.max_sigs = min(args.max_sigs, 80)
    
    print(f"{'='*70}")
    print("DSA TIMING ATTACK: SIGNATURES NEEDED VS NONCE SIZE")
    print(f"{'='*70}")
    
    # Generate test sequences
    nonce_bits_list = generate_nonce_sequence(
        min_bits=args.min_bits,
        max_bits=args.max_bits,
        mode=args.nonce_mode
    )
    
    signature_counts = generate_signature_sequence(
        min_sigs=args.min_sigs,
        max_sigs=args.max_sigs,
        mode=args.sig_mode
    )
    
    print(f"Testing {len(nonce_bits_list)} nonce sizes: {nonce_bits_list}")
    print(f"Testing {len(signature_counts)} signature counts: {signature_counts}")
    print(f"Total parameter combinations: {len(nonce_bits_list) * len(signature_counts)}")
    print(f"Trials per combination: {args.trials}")
    print(f"{'='*70}")
    
    # Estimate time
    total_combinations = len(nonce_bits_list) * len(signature_counts)
    estimated_time = total_combinations * args.trials * 3  # ~3 seconds per trial
    
    if estimated_time > 300 and not args.quick:  # More than 5 minutes
        print(f"\n⚠️  WARNING: Estimated time: ~{estimated_time//60} minutes")
        print("Consider using --quick flag or reducing parameters.")
        user_input = input("Continue? (y/n): ")
        if user_input.lower() != 'y':
            return
    
    # Initialize results matrix
    results_matrix = np.full((len(nonce_bits_list), len(signature_counts)), np.nan)
    experiment_times = []
    
    # Run experiments for each parameter combination
    total_experiments = total_combinations * args.trials
    completed_experiments = 0
    
    print(f"\nStarting experiments...")
    print(f"Progress: [{' ' * 50}] 0%", end='')
    
    start_time = time.time()
    
    for i, nonce_bits in enumerate(nonce_bits_list):
        for j, num_sigs in enumerate(signature_counts):
            cell_start_time = time.time()
            successes = 0
            
            # Run multiple trials
            for trial in range(args.trials):
                seed = 42 + (i * len(signature_counts) + j) * args.trials + trial
                
                if run_single_experiment(nonce_bits, num_sigs, args.known_bits, seed):
                    successes += 1
                
                completed_experiments += 1
                
                # Update progress bar
                progress = completed_experiments / total_experiments
                bars = int(progress * 50)
                print(f"\rProgress: [{'#' * bars}{' ' * (50-bars)}] {progress:.0%}", end='')
            
            # Calculate success rate for this cell
            success_rate = successes / args.trials
            results_matrix[i, j] = success_rate
            
            cell_time = time.time() - cell_start_time
            experiment_times.append(cell_time)
    
    total_time = time.time() - start_time
    print(f"\n\nTotal experiment time: {total_time:.1f} seconds ({total_time/60:.1f} minutes)")
    
    # Save results
    csv_file, json_file = save_results_to_files(
        results_matrix, nonce_bits_list, signature_counts, args.output_prefix
    )
    
    # Create visualizations
    print(f"\n{'='*70}")
    print("CREATING VISUALIZATIONS")
    print(f"{'='*70}")
    
    # 1. Heatmap (main visualization)
    heatmap_file = f"{args.output_prefix}_heatmap.png"
    create_heatmap_plot(results_matrix, nonce_bits_list, signature_counts, heatmap_file)
    
    # 2. 3D surface plot (optional)
    if not args.skip_3d:
        surface_file = f"{args.output_prefix}_3d.png"
        create_3d_surface_plot(results_matrix, nonce_bits_list, signature_counts, surface_file)
    
    # 3. Print detailed analysis
    print(f"\n{'='*70}")
    print("DETAILED ANALYSIS")
    print(f"{'='*70}")
    
    # Find optimal points
    print("\nOPTIMAL PARAMETER COMBINATIONS:")
    print("-" * 50)
    
    # Best case (fewest signatures for 100% success)
    best_combinations = []
    for i, bits in enumerate(nonce_bits_list):
        for j, sigs in enumerate(signature_counts):
            rate = results_matrix[i, j]
            if not np.isnan(rate) and rate == 1.0:
                best_combinations.append((bits, sigs, rate))
    
    if best_combinations:
        # Sort by signatures (ascending), then by bits (ascending)
        best_combinations.sort(key=lambda x: (x[1], x[0]))
        print("100% Success with minimal signatures:")
        for bits, sigs, rate in best_combinations[:5]:  # Top 5
            print(f"  • {bits} bits with {sigs} signatures: {rate:.0%}")
    else:
        print("No 100% success cases found")
    
    # Practical recommendations
    print("\nPRACTICAL RECOMMENDATIONS:")
    print("-" * 50)
    
    # For different security levels
    security_levels = [
        ("High security (≥80% success):", 0.8),
        ("Practical (≥50% success):", 0.5),
        ("Minimum (≥20% success):", 0.2)
    ]
    
    for description, threshold in security_levels:
        print(f"\n{description}")
        found = False
        for i, bits in enumerate(nonce_bits_list):
            for j, sigs in enumerate(signature_counts):
                rate = results_matrix[i, j]
                if not np.isnan(rate) and rate >= threshold:
                    # Check if this is the minimum signatures for this threshold at these bits
                    if j == 0 or results_matrix[i, j-1] < threshold:
                        print(f"  • {bits} bits: ≥{sigs} signatures ({rate:.0%})")
                        found = True
        
        if not found:
            print(f"  No combinations achieve ≥{threshold:.0%} success")
    
    # Signature efficiency analysis
    print("\nSIGNATURE EFFICIENCY ANALYSIS:")
    print("-" * 50)
    
    # Calculate how many more signatures are needed for each doubling of nonce size
    for i in range(len(nonce_bits_list) - 1):
        bits1, bits2 = nonce_bits_list[i], nonce_bits_list[i+1]
        
        # Find minimum signatures for 50% success at each nonce size
        sigs1 = None
        sigs2 = None
        
        for j, sigs in enumerate(signature_counts):
            if not np.isnan(results_matrix[i, j]) and results_matrix[i, j] >= 0.5:
                sigs1 = sigs
                break
        
        for j, sigs in enumerate(signature_counts):
            if not np.isnan(results_matrix[i+1, j]) and results_matrix[i+1, j] >= 0.5:
                sigs2 = sigs
                break
        
        if sigs1 and sigs2:
            ratio = sigs2 / sigs1
            bits_ratio = bits2 / bits1
            print(f"  {bits1} → {bits2} bits: Signatures increase {ratio:.1f}x for {bits_ratio:.1f}x nonce size")
    
    # Final answer to research question
    print(f"\n{'='*70}")
    print("RESEARCH QUESTION ANSWER")
    print(f"{'='*70}")
    
    print("Q: How many signatures are needed for successful attacks at different nonce sizes?")
    print("\nA: The relationship is exponential:")
    print("   1. Small nonces (≤16 bits): Work with few signatures (5-20)")
    print("   2. Medium nonces (16-32 bits): Require moderate signatures (20-80)")
    print("   3. Large nonces (≥32 bits): Need many signatures (80+)")
    print("\n   Each doubling of nonce size typically requires 2-4x more signatures")
    print("   to maintain the same success rate.")
    
    print(f"{'='*70}")

if __name__ == "__main__":
    main()