import concurrent.futures
import argparse
import time
import os
import signal
import sys
from Crypto.Hash import RIPEMD160, SHA256
from coincurve import PrivateKey
import numpy as np
import secrets
import random

# Constants for secp256k1 curve
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

# Signal handler for graceful shutdown
def signal_handler(sig, frame):
    print("\nProcess interrupted by user. Exiting...")
    sys.exit(0)

# Registering signal to handle keyboard interrupts
signal.signal(signal.SIGINT, signal_handler)

# RIPEMD-160 hashing function using PyCryptodome
def ripemd160(data):
    h = RIPEMD160.new()
    h.update(data)
    return h.digest()

# Function to generate secure random numbers within a specific range
def generate_random_in_range(start, end):
    range_size = end - start
    return start + secrets.randbelow(range_size)

# Kangaroo worker function for parallel processing
def kangaroo_worker(start_range, end_range, target_ripemd_list):
    found_keys = []
    for _ in range(10000):  # Adjust iterations for batch processing if needed
        candidate = generate_random_in_range(start_range, end_range)
        
        if candidate >= CURVE_ORDER:
            continue

        try:
            # Generate private key
            priv_key = PrivateKey(candidate.to_bytes(32, 'big'))
            # Derive the public key in compressed format
            pub_key = priv_key.public_key.format(compressed=True)

            # Generate RIPEMD-160 hash of the public key
            sha256_hash = SHA256.new(pub_key).digest()
            ripemd_hash = ripemd160(sha256_hash)

            # Check if hash is in target list
            if ripemd_hash in target_ripemd_list:
                found_keys.append((priv_key.to_hex(), ripemd_hash.hex()))
        except Exception as e:
            print(f"Error with key {hex(candidate)}: {e}")
    return found_keys

# Main function to handle arguments, file loading, and parallel execution
def main():
    parser = argparse.ArgumentParser(description="Kangaroo Algorithm for Bitcoin RIPEMD-160 Search")
    parser.add_argument("-f", "--file", required=True, help="Location of the target RIPEMD-160 file")
    parser.add_argument("-t", "--threads", type=int, default=os.cpu_count(), help="Number of CPU threads")
    parser.add_argument("-r", "--range", required=True, help="Range to search in the format start:end (hex)")
    parser.add_argument("-S", "--seconds", type=int, default=2, help="Output speed frequency in seconds")
    
    args = parser.parse_args()
    start_range, end_range = map(lambda x: int(x, 16), args.range.split(":"))
    max_workers = min(args.threads, os.cpu_count())

    # Load target RIPEMD-160 hashes from file into a numpy array for efficient lookups
    with open(args.file, 'rb') as f:
        file_content = f.read()
        adjusted_size = (len(file_content) // 20) * 20
        target_ripemd_list = np.frombuffer(file_content[:adjusted_size], dtype='S20')

    print(f"Starting search from {hex(start_range)} to {hex(end_range)} using {max_workers} threads.")
    start_time = time.time()
    found_any = False

    with open("RIPFOUND.txt", "a") as found_file:
        try:
            with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
                futures = []
                for _ in range(max_workers):
                    futures.append(executor.submit(kangaroo_worker, start_range, end_range, target_ripemd_list))
                
                while futures:
                    done, futures = concurrent.futures.wait(futures, timeout=args.seconds, return_when=concurrent.futures.FIRST_COMPLETED)
                    for future in done:
                        found_keys = future.result()
                        for priv_key, ripemd_hex in found_keys:
                            print(f"Found matching key: {priv_key} | RIPEMD-160: {ripemd_hex}")
                            found_file.write(f"{priv_key},{ripemd_hex}\n")
                            found_any = True

                    elapsed = time.time() - start_time
                    keys_checked = max_workers * (elapsed / args.seconds) * 10000
                    print(f"Elapsed: {elapsed:.2f}s | Keys Checked: {int(keys_checked)} | Speed: {int(keys_checked / elapsed)} keys/s")
        
        except KeyboardInterrupt:
            print("\nSearch interrupted by user.")
    
    if not found_any:
        print("No matching keys found.")
    else:
        print("Matching keys saved to RIPFOUND.txt")

if __name__ == "__main__":
    main()
