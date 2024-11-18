import os
import time
import random
import hashlib
import argparse
from multiprocessing import Process, Value, Event
from fastecdsa.curve import secp256k1
from fastecdsa.point import Point as FECPoint
from Crypto.Hash import RIPEMD160, SHA256
from coincurve import PrivateKey

# Define secp256k1 constants
SECP256K1_ORDER = secp256k1.q
G = secp256k1.G

# Pre-compute 2^k * G for k = 0 to 255
PRECOMPUTED_STEPS = {2**k: k * G for k in range(256)}

# RIPEMD-160 hash computation
def private_key_to_ripemd160(private_key):
    priv_key_obj = PrivateKey(private_key)
    public_key = priv_key_obj.public_key.format(compressed=True)
    sha256_hash = SHA256.new(public_key).digest()
    return RIPEMD160.new(sha256_hash).digest().hex()

# Load target hashes
def load_targets(file_path):
    try:
        with open(file_path, 'r') as f:
            return set(line.strip() for line in f)
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return set()

# Kangaroo algorithm for private key search
def kangaroo_search(public_point, targets, start_key, end_key, stop_event, generated_count, found_file, kangaroo_id):
    current_point = public_point
    local_count = 0
    
    while not stop_event.is_set():
        # Convert the point to bytes and compute step size
        point_bytes = current_point.x.to_bytes(32, 'big') + current_point.y.to_bytes(32, 'big')
        step_size = (int(hashlib.sha256(point_bytes).hexdigest(), 16) % 256) + 1
        
        # Update current point by adding step_size * G (which is a scalar multiplication)
        current_point += step_size * G

        # Check if current point matches a precomputed step
        if current_point in PRECOMPUTED_STEPS:
            private_key = PRECOMPUTED_STEPS[current_point]
            ripemd160_hash = private_key_to_ripemd160(private_key.to_bytes(32, 'big'))

            if ripemd160_hash in targets:
                with open(found_file, 'a') as f:
                    f.write(f"Kangaroo {kangaroo_id} found key:\nPrivate Key: {private_key}\nRIPEMD-160 Hash: {ripemd160_hash}\n\n")
                stop_event.set()
                break

        # Increment counters
        local_count += 1
        with generated_count.get_lock():
            generated_count.value += 1

# Display statistics
def display_statistics(generated_count, start_time, stop_event, kangaroo_count):
    while not stop_event.is_set():
        time.sleep(1)
        elapsed_time = time.time() - start_time
        with generated_count.get_lock():
            keys_generated = generated_count.value
        keys_per_second = keys_generated / elapsed_time if elapsed_time > 0 else 0
        print(f"\r[+ Keys Generated: {keys_generated} | Speed: {keys_per_second:.2f} keys/s | Kangaroos: {kangaroo_count}]", end="", flush=True)

# Main function
def main():
    parser = argparse.ArgumentParser(description="Optimized Kangaroo Algorithm with Parallel Processing.")
    parser.add_argument('-f', '--file', required=True, help="File containing target RIPEMD-160 hashes")
    parser.add_argument('-k', '--kangaroos', type=int, default=1, help="Number of parallel kangaroos")
    parser.add_argument('-s', '--start', type=int, default=1, help="Start of private key range")
    parser.add_argument('-e', '--end', type=int, default=SECP256K1_ORDER - 1, help="End of private key range")
    parser.add_argument('-o', '--output', default='found_keys.txt', help="Output file for results")
    args = parser.parse_args()

    targets = load_targets(args.file)
    if not targets:
        print("No targets loaded. Exiting.")
        return

    generated_count = Value('i', 0)
    stop_event = Event()
    start_time = time.time()

    # Launch kangaroos
    kangaroo_processes = []
    
    for i in range(args.kangaroos):
        # Generate a valid public point using a random scalar from the entire valid key space.
        random_scalar = random.randint(1, SECP256K1_ORDER - 1)  # Ensure this is within valid range
        
        public_point = random_scalar * G  # This ensures public_point is on the curve
        
        process = Process(target=kangaroo_search,
                          args=(public_point,
                                targets,
                                args.start,
                                args.end,
                                stop_event,
                                generated_count,
                                args.output,
                                i + 1))
        
        kangaroo_processes.append(process)
        process.start()

    # Display statistics
    stats_process = Process(target=display_statistics,
                            args=(generated_count,
                                  start_time,
                                  stop_event,
                                  args.kangaroos))
    
    stats_process.start()

    # Wait for processes to complete
    for process in kangaroo_processes:
        process.join()

    stop_event.set()
    stats_process.join()
    
    print("\nSearch complete.")

if __name__ == '__main__':
    main()