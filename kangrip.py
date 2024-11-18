import os
import time
import hashlib
import argparse
import random
from multiprocessing import Process, Value, Lock, Event
from Crypto.Hash import RIPEMD160, SHA256
from coincurve import PrivateKey

# Define secp256k1 order for the private key range
SECP256K1_ORDER = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140", 16)

# Generation threshold for range shuffling
RANGE_SHUFFLE_THRESHOLD = 68719476736

# Private key generation function
def generate_private_key(random_mode=True, sequence=None, start_key=1, end_key=SECP256K1_ORDER):
    if random_mode:
        return os.urandom(32)
    elif sequence is not None:
        return (start_key + sequence).to_bytes(32, 'big')
    else:
        raise ValueError("Specify a valid mode for private key generation")

# RIPEMD-160 hash function for compressed and uncompressed keys
def private_key_to_ripemd160(private_key):
    priv_key_obj = PrivateKey(private_key)
    public_key = priv_key_obj.public_key.format(compressed=True)
    uncompressed_key = priv_key_obj.public_key.format(compressed=False)

    sha256_hash_compressed = SHA256.new(public_key).digest()
    sha256_hash_uncompressed = SHA256.new(uncompressed_key).digest()

    ripemd160_compressed = RIPEMD160.new(sha256_hash_compressed).digest()
    ripemd160_uncompressed = RIPEMD160.new(sha256_hash_uncompressed).digest()

    return ripemd160_compressed, ripemd160_uncompressed

# Target hash loading function
def load_targets(file_path):
    targets = set()
    try:
        with open(file_path, 'r') as f:
            for line in f:
                targets.add(line.strip())
    except FileNotFoundError:
        print(f"Error: Target file '{file_path}' not found.")
    return targets

# Worker function for each kangaroo
def scan_worker(start, step, targets, random_mode, sequence_scan, start_key, end_key, stop_event, generated_count, lock, found_file, kangaroo_id, loop_count, matches_found):
    sequence = start if sequence_scan else None
    local_generation_count = 0
    while not stop_event.is_set():
        if sequence is not None and (sequence < start_key if step < 0 else sequence > end_key):
            with loop_count.get_lock():
                loop_count.value += 1
            sequence = start

        private_key = generate_private_key(random_mode=random_mode, sequence=sequence, start_key=start_key, end_key=end_key)
        compressed, uncompressed = private_key_to_ripemd160(private_key)

        with lock:
            generated_count.value += 1
            local_generation_count += 1

        # Check if the generated hashes match any target
        if compressed.hex() in targets or uncompressed.hex() in targets:
            with open(found_file, 'a') as f:
                f.write(f"Kangaroo {kangaroo_id} found key:\nPrivate Key: {private_key.hex()}\nRIPEMD-160 Hash: {compressed.hex() if compressed.hex() in targets else uncompressed.hex()}\n\n")
            with matches_found.get_lock():
                matches_found.value += 1

        # Shuffle range for this kangaroo after a threshold of generations
        if local_generation_count >= RANGE_SHUFFLE_THRESHOLD:
            process_start = random.randint(start_key, end_key - step)
            process_end = min(process_start + (end_key - start_key) // 10, end_key)
            print(f"\n[Range Shuffle] Launching K{kangaroo_id} to new range :: {{ {hex(process_start)} : {hex(process_end)} }}")
            sequence = process_start if sequence_scan else None
            local_generation_count = 0  # Reset local count after shuffling

        sequence += step

# Statistics display function
def display_statistics(generated_count, start_time, stop_event, kangaroo_count, loop_count, matches_found):
    while not stop_event.is_set():
        time.sleep(1)
        elapsed_time = time.time() - start_time
        with generated_count.get_lock(), loop_count.get_lock(), matches_found.get_lock():
            total_keys = generated_count.value
            loop = loop_count.value
            matches = matches_found.value
        keys_per_second = total_keys / elapsed_time if elapsed_time > 0 else 0
        print(f"\r[+ Total keys generated: {total_keys}][Speed: {keys_per_second:.2f} Keys/s][Kangaroos launched: {kangaroo_count}][Loop: {loop}][Matches found: {matches}]", end="", flush=True)

# Main function to launch kangaroo workers
def scan_keys(targets, random_mode, sequence_scan, reverse, kangaroo_count, start_key, end_key, found_file):
    generated_count = Value('i', 0)
    loop_count = Value('i', 0)
    matches_found = Value('i', 0)
    lock = Lock()
    stop_event = Event()

    step = -1 if reverse else 1
    range_step = (end_key - start_key) // kangaroo_count
    start_time = time.time()

    stats_process = Process(target=display_statistics, args=(generated_count, start_time, stop_event, kangaroo_count, loop_count, matches_found))
    stats_process.start()

    process_list = []
    for i in range(kangaroo_count):
        process_start = start_key + i * range_step
        process_end = min(process_start + range_step, end_key)
        print(f"Launching K{i + 1}: from range :: {{ {hex(process_start)} : {hex(process_end)} }}")

        process = Process(
            target=scan_worker,
            args=(process_start, step, targets, random_mode, sequence_scan, start_key, end_key, stop_event, generated_count, lock, found_file, i + 1, loop_count, matches_found)
        )
        process.daemon = True
        process.start()
        process_list.append(process)

    for process in process_list:
        process.join()

    stop_event.set()
    stats_process.join()
    print(f"\nFinal total keys generated: {generated_count.value}")

# Main entry point with argument parsing
def main():
    parser = argparse.ArgumentParser(description="Kangaroo algorithm with RIPEMD-160 hash matching.")
    parser.add_argument('-f', '--file', type=str, required=True, help="Path to the file containing target RIPEMD-160 hashes")
    parser.add_argument('-R', '--random', action='store_true', help="Enable random mode for private key generation")
    parser.add_argument('-S', '--sequence', action='store_true', help="Enable sequence mode for private key generation")
    parser.add_argument('-k', '--kangaroos', type=int, default=1, help="Number of kangaroos to launch within the range")
    parser.add_argument('-s', '--start', type=int, default=1, help="Starting key for sequential scan")
    parser.add_argument('-e', '--end', type=int, default=SECP256K1_ORDER, help="Ending key for the scan range")
    parser.add_argument('-o', '--output', type=str, default='found_keys.txt', help="Output file to store found private keys")
    parser.add_argument('-r', '--reverse', action='store_true', help="Enable reverse scan direction")

    args = parser.parse_args()

    targets = load_targets(args.file)
    if not targets:
        print("No targets loaded. Exiting.")
        return

    scan_keys(
        targets=targets,
        random_mode=args.random,
        sequence_scan=args.sequence,
        reverse=args.reverse,
        kangaroo_count=args.kangaroos,
        start_key=args.start,
        end_key=args.end,
        found_file=args.output
    )

if __name__ == '__main__':
    main()
