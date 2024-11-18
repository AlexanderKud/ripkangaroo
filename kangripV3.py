import concurrent.futures
import argparse
import time
import os
import signal
import sys
from Crypto.Hash import RIPEMD160, SHA256
from coincurve import PrivateKey
import numpy as np

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

# Kangaroo worker function for parallel processing
def kangaroo_worker(start_range, end_range, target_ripemd_list):
    found_keys = []
    generated_outputs = []
    for candidate in range(start_range, end_range):
        if candidate >= CURVE_ORDER:
            break
        try:
            # Generate private key
            priv_key = PrivateKey(candidate.to_bytes(32, 'big'))
            # Derive the public key in compressed format
            pub_key = priv_key.public_key.format(compressed=True)
            
            # Generate RIPEMD-160 hash of the public key
            sha256_hash = SHA256.new(pub_key).digest()
            ripemd_hash = ripemd160(sha256_hash)
            
            # Save all generated outputs
            generated_outputs.append(f"{priv_key.to_hex()},{ripemd_hash.hex()}\n")
            
            # Check if hash is in target list
            if ripemd_hash in target_ripemd_list:
                found_keys.append((priv_key.to_hex(), ripemd_hash.hex()))
        except Exception as e:
            print(f"Error with key {hex(candidate)}: {e}")
    return found_keys, generated_outputs

# Main function to handle arguments, file loading, and parallel execution
def main():
    # Argument parsing for CLI options
    parser = argparse.ArgumentParser(description="Kangaroo Algorithm for Bitcoin RIPEMD-160 Search")
    parser.add_argument("-f", "--file", required=True, help="Location of the target RIPEMD-160 file")
    parser.add_argument("-t", "--threads", type=int, default=os.cpu_count(), help="Number of CPU threads")
    parser.add_argument("-r", "--range", required=True, help="Range to search in the format start:end (hex)")
    parser.add_argument("-S", "--seconds", type=int, default=2, help="Output speed frequency in seconds")
    
    # Parse arguments and assign range and thread counts
    args = parser.parse_args()
    start_range, end_range = map(lambda x: int(x, 16), args.range.split(":"))
    max_workers = min(args.threads, os.cpu_count())
    
    # Load target RIPEMD-160 hashes from file into a numpy array for efficient lookups
    with open(args.file, 'rb') as f:
        file_content = f.read()
        # Truncate to a multiple of 20 bytes to match RIPEMD-160 hashes
        adjusted_size = (len(file_content) // 20) * 20
        target_ripemd_list = np.frombuffer(file_content[:adjusted_size], dtype='S20')

    print(f"Starting search from {hex(start_range)} to {hex(end_range)} using {max_workers} threads.")
    start_time = time.time()
    found_any = False

    # Open output files for all generated keys and matches
    with open("RIPFOUND.txt", "a") as found_file, open("found.txt", "a") as all_file:
        try:
            with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
                futures = []
                step_size = (end_range - start_range) // max_workers
                
                # Dispatching tasks to each worker
                for i in range(max_workers):
                    s = start_range + i * step_size
                    e = s + step_size if i < max_workers - 1 else end_range
                    futures.append(executor.submit(kangaroo_worker, s, e, target_ripemd_list))
                
                # Monitor results and display progress
                while futures:
                    done, futures = concurrent.futures.wait(futures, timeout=args.seconds, return_when=concurrent.futures.FIRST_COMPLETED)
                    for future in done:
                        found_keys, generated_outputs = future.result()
                        
                        # Write all generated outputs to found.txt
                        all_file.writelines(generated_outputs)
                        
                        # Write matching keys to RIPFOUND.txt
                        for priv_key, ripemd_hex in found_keys:
                            print(f"Found matching key: {priv_key} | RIPEMD-160: {ripemd_hex}")
                            found_file.write(f"{priv_key},{ripemd_hex}\n")
                            found_any = True

                    elapsed = time.time() - start_time
                    keys_checked = step_size * max_workers * (elapsed / args.seconds)
                    print(f"Elapsed: {elapsed:.2f}s | Keys Checked: {int(keys_checked)} | Speed: {int(keys_checked / elapsed)} keys/s")
        
        except KeyboardInterrupt:
            print("\nSearch interrupted by user.")
    
    # Summary of results
    if not found_any:
        print("No matching keys found.")
    else:
        print("Matching keys saved to RIPFOUND.txt")

if __name__ == "__main__":
    main()
