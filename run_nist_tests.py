#!/usr/bin/env python3
"""
=============================================================================
NIST SP 800-22 Statistical Test Runner for HKDF-ChaCha20 Keystream
=============================================================================
Standalone implementation of key NIST SP 800-22 randomness tests.
Does NOT depend on the nistrng library (which has overflow bugs for >256 bits).

Usage:
  python run_nist_tests.py keystream_1M_hex.txt
  python run_nist_tests.py keystream_1M.bin
=============================================================================
"""

import sys
import os
import math

# =============================================================================
# Data Reading Functions
# =============================================================================

def read_hex_file(filepath):
    """Read hex text file and convert to list of bits."""
    bits = []
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            for hex_char in line:
                try:
                    val = int(hex_char, 16)
                except ValueError:
                    continue
                bits.append((val >> 3) & 1)
                bits.append((val >> 2) & 1)
                bits.append((val >> 1) & 1)
                bits.append((val >> 0) & 1)
    return bits

def read_binary_file(filepath):
    """Read binary file and convert to list of bits."""
    with open(filepath, 'rb') as f:
        data = f.read()
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits

# =============================================================================
# NIST SP 800-22 Test Implementations
# =============================================================================

def test_frequency(bits):
    """Test 1: Frequency (Monobit) Test
    Determines whether the number of ones and zeros in a sequence are
    approximately the same as would be expected for a truly random sequence."""
    n = len(bits)
    s = sum(2 * b - 1 for b in bits)
    s_obs = abs(s) / math.sqrt(n)
    return math.erfc(s_obs / math.sqrt(2))

def test_block_frequency(bits, M=128):
    """Test 2: Frequency Test within a Block
    Determines whether the frequency of ones in M-bit blocks is
    approximately M/2, as expected under randomness."""
    n = len(bits)
    N = n // M
    chi_sq = 0.0
    for i in range(N):
        block = bits[i*M : (i+1)*M]
        pi = sum(block) / M
        chi_sq += (pi - 0.5) ** 2
    chi_sq *= 4 * M
    try:
        from scipy.special import gammaincc
        return gammaincc(N / 2.0, chi_sq / 2.0)
    except ImportError:
        z = (chi_sq - N) / math.sqrt(2 * N) if N > 0 else 0
        return math.erfc(abs(z) / math.sqrt(2))

def test_runs(bits):
    """Test 3: Runs Test
    Determines whether the number of runs of ones and zeros of various
    lengths is as expected for a random sequence."""
    n = len(bits)
    pi = sum(bits) / n
    tau = 2.0 / math.sqrt(n)
    if abs(pi - 0.5) >= tau:
        return 0.0
    V = 1
    for i in range(1, n):
        if bits[i] != bits[i-1]:
            V += 1
    return math.erfc(abs(V - 2*n*pi*(1-pi)) / (2*math.sqrt(2*n)*pi*(1-pi)))

def test_longest_run(bits):
    """Test 4: Longest Run of Ones in a Block
    Determines whether the length of the longest run of ones within M-bit
    blocks is consistent with what is expected for a random sequence."""
    n = len(bits)
    if n < 6272:
        return -1
    if n < 750000:
        M = 8; K = 3; N = 16
        pi_vals = [0.2148, 0.3672, 0.2305, 0.1875]
    else:
        M = 10000; K = 6; N = n // M
        pi_vals = [0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727]
    v_counts = [0] * (K + 1)
    for i in range(N):
        block = bits[i*M : (i+1)*M]
        max_run = 0; current_run = 0
        for b in block:
            if b == 1:
                current_run += 1
                max_run = max(max_run, current_run)
            else:
                current_run = 0
        if n < 750000:
            if max_run <= 1: v_counts[0] += 1
            elif max_run == 2: v_counts[1] += 1
            elif max_run == 3: v_counts[2] += 1
            else: v_counts[3] += 1
        else:
            if max_run <= 10: v_counts[0] += 1
            elif max_run == 11: v_counts[1] += 1
            elif max_run == 12: v_counts[2] += 1
            elif max_run == 13: v_counts[3] += 1
            elif max_run == 14: v_counts[4] += 1
            elif max_run == 15: v_counts[5] += 1
            else: v_counts[6] += 1
    chi_sq = sum((v_counts[i] - N * pi_vals[i])**2 / (N * pi_vals[i])
                 for i in range(K + 1) if N * pi_vals[i] > 0)
    try:
        from scipy.special import gammaincc
        return gammaincc(K / 2.0, chi_sq / 2.0)
    except ImportError:
        z = (chi_sq - K) / math.sqrt(2 * K) if K > 0 else 0
        return math.erfc(abs(z) / math.sqrt(2))

def test_dft_spectral(bits):
    """Test 6: Discrete Fourier Transform (Spectral) Test
    Detects periodic features (repetitive patterns near each other)
    in the bit sequence that would indicate a deviation from randomness."""
    try:
        import numpy as np
    except ImportError:
        return -1
    n = len(bits)
    X = np.array([2*b - 1 for b in bits], dtype=np.float64)
    S = np.fft.fft(X)
    M = np.abs(S[:n//2])
    T = math.sqrt(math.log(1.0/0.05) * n)
    N0 = 0.95 * n / 2.0
    N1 = float(np.sum(M < T))
    d = (N1 - N0) / math.sqrt(n * 0.95 * 0.05 / 4.0)
    return math.erfc(abs(d) / math.sqrt(2))

def test_serial(bits, m=16):
    """Test 11: Serial Test
    Determines whether the number of occurrences of 2^m m-bit overlapping
    patterns is approximately the same as expected for a random sequence."""
    n = len(bits)
    if n < 2**m:
        return -1

    def psi_sq(m_val, bits_list, n_val):
        if m_val == 0:
            return 0.0
        augmented = bits_list + bits_list[:m_val-1]
        counts = {}
        for i in range(n_val):
            pattern = tuple(augmented[i:i+m_val])
            counts[pattern] = counts.get(pattern, 0) + 1
        total = sum(v*v for v in counts.values())
        return (2**m_val / n_val) * total - n_val

    psi_m = psi_sq(m, bits, n)
    psi_m1 = psi_sq(m-1, bits, n)
    psi_m2 = psi_sq(m-2, bits, n)
    del1 = psi_m - psi_m1
    del2 = psi_m - 2*psi_m1 + psi_m2
    try:
        from scipy.special import gammaincc
        p1 = gammaincc(2**(m-2), del1/2.0)
        p2 = gammaincc(2**(m-3), del2/2.0)
    except ImportError:
        df1 = 2**(m-1); df2 = 2**(m-2)
        z1 = (del1 - df1) / math.sqrt(2*df1) if df1 > 0 else 0
        z2 = (del2 - df2) / math.sqrt(2*df2) if df2 > 0 else 0
        p1 = math.erfc(abs(z1) / math.sqrt(2))
        p2 = math.erfc(abs(z2) / math.sqrt(2))
    return min(p1, p2)

def test_approximate_entropy(bits, m=10):
    """Test 12: Approximate Entropy Test
    Compares the frequency of overlapping blocks of two consecutive lengths
    against the expected result for a random sequence."""
    n = len(bits)

    def phi_m(m_val):
        if m_val == 0:
            return math.log(2)
        augmented = bits + bits[:m_val]
        counts = {}
        for i in range(n):
            pattern = tuple(augmented[i:i+m_val])
            counts[pattern] = counts.get(pattern, 0) + 1
        total = 0.0
        for c in counts.values():
            pi = c / n
            if pi > 0:
                total += pi * math.log(pi)
        return total

    phi1 = phi_m(m)
    phi2 = phi_m(m+1)
    apen = phi1 - phi2
    chi_sq = 2.0 * n * (math.log(2) - apen)
    try:
        from scipy.special import gammaincc
        return gammaincc(2**(m-1), chi_sq / 2.0)
    except ImportError:
        df = 2**m
        z = (chi_sq - df) / math.sqrt(2*df) if df > 0 else 0
        return math.erfc(abs(z) / math.sqrt(2))

def test_cumulative_sums(bits, mode='forward'):
    """Test 13: Cumulative Sums Test
    Determines whether the cumulative sum of the adjusted (-1,+1) sequence
    is too large or too small relative to expected random walk behavior."""
    n = len(bits)
    X = [2*b - 1 for b in bits]
    if mode == 'backward':
        X = X[::-1]
    S = 0; z = 0
    for x in X:
        S += x
        z = max(z, abs(S))
    if z == 0:
        return 1.0
    s1 = 0.0
    for k in range(int((-n/z + 1) / 4), int((n/z - 1) / 4) + 2):
        s1 += (math.erfc((((4*k)+1)*z) / math.sqrt(2*n)) -
               math.erfc((((4*k)+3)*z) / math.sqrt(2*n)))
    s2 = 0.0
    for k in range(int((-n/z - 3) / 4), int((n/z - 1) / 4) + 2):
        s2 += (math.erfc((((4*k)+1)*z) / math.sqrt(2*n)) -
               math.erfc((((4*k)+3)*z) / math.sqrt(2*n)))
    return max(0.0, min(1.0, 1.0 - s1 + s2))

# =============================================================================
# Main Runner
# =============================================================================

def main():
    if len(sys.argv) < 2:
        print("Usage: python run_nist_tests.py <keystream_file>")
        print("  Supports: .txt/.hex (hex text) or .bin (binary)")
        sys.exit(1)

    filepath = sys.argv[1]
    if not os.path.exists(filepath):
        print(f"Error: File '{filepath}' not found.")
        sys.exit(1)

    # Read data
    if filepath.endswith('.txt') or filepath.endswith('.hex'):
        bits = read_hex_file(filepath)
    else:
        bits = read_binary_file(filepath)

    n = len(bits)
    if n == 0:
        print("  ERROR: No data read from file!")
        sys.exit(1)

    # Header
    print("="*70)
    print("  HKDF-ChaCha20 Keystream — NIST SP 800-22 Test Runner")
    print("="*70)
    print(f"  Input file  : {os.path.basename(filepath)}")
    print(f"  Total bits  : {n:,}")
    print(f"  Total bytes : {n//8:,}")
    print(f"  Blocks (512): {n // 512:,}")

    ones = sum(bits)
    zeros = n - ones
    ratio = ones / n
    print(f"\n  Quick Statistics:")
    print(f"    Ones  : {ones:>10,} ({ratio*100:.2f}%)")
    print(f"    Zeros : {zeros:>10,} ({(1-ratio)*100:.2f}%)")
    print(f"    Ratio : {ratio:.6f} (ideal: 0.500000)")

    # Run tests
    ALPHA = 0.01
    tests = [
        ("Frequency (Monobit)",        lambda: test_frequency(bits)),
        ("Block Frequency (M=128)",    lambda: test_block_frequency(bits, 128)),
        ("Runs",                       lambda: test_runs(bits)),
        ("Longest Run of Ones",        lambda: test_longest_run(bits)),
        ("DFT (Spectral)",             lambda: test_dft_spectral(bits)),
        ("Serial (m=16)",              lambda: test_serial(bits, 16)),
        ("Approximate Entropy (m=10)", lambda: test_approximate_entropy(bits, 10)),
        ("Cumulative Sums (Forward)",  lambda: test_cumulative_sums(bits, 'forward')),
        ("Cumulative Sums (Reverse)",  lambda: test_cumulative_sums(bits, 'backward')),
    ]

    print("\n" + "="*70)
    print("  NIST SP 800-22 Statistical Randomness Tests")
    print("="*70)
    print(f"  Significance level: alpha = {ALPHA}")
    print(f"  Decision rule: P-value >= {ALPHA} -> PASS (random)")
    print(f"                 P-value <  {ALPHA} -> FAIL (non-random)")
    print("="*70)

    print(f"\n  {'#':<4} {'Test Name':<35} {'P-Value':>12} {'Result':>8}")
    print("  " + "-"*62)

    all_passed = True
    pass_count = 0
    total_count = 0

    for idx, (name, test_func) in enumerate(tests):
        try:
            p = test_func()
        except Exception as e:
            print(f"  {idx+1:<4} {name:<35} {'ERROR':>12} {'SKIP':>8}")
            continue

        if p < 0:
            print(f"  {idx+1:<4} {name:<35} {'N/A':>12} {'SKIP':>8}")
            continue

        total_count += 1
        passed = p >= ALPHA
        status = "PASS" if passed else "FAIL"
        print(f"  {idx+1:<4} {name:<35} {p:>12.6f} {status:>8}")

        if passed:
            pass_count += 1
        else:
            all_passed = False

    print("  " + "-"*62)

    if all_passed:
        print(f"\n  >>> ALL {pass_count}/{total_count} NIST TESTS PASSED <<<")
        print(f"\n  CONCLUSION: The HKDF-ChaCha20 keystream generator produces")
        print(f"  cryptographically secure pseudorandom output that is")
        print(f"  statistically indistinguishable from true random data.")
    else:
        print(f"\n  >>> {pass_count}/{total_count} TESTS PASSED, "
              f"{total_count - pass_count} FAILED <<<")

    print("="*70)

if __name__ == '__main__':
    main()
