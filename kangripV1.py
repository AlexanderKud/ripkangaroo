import os
import time
import hashlib
from ecdsa import SECP256k1, SigningKey
from multiprocessing import Process, Value, Lock, Event, cpu_count
import argparse

SECP256K1_ORDER = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140", 16)

def load_targets(file_path):
    """Load target RIPEMD-160 hashes from a file."""
    try:
        with open(file_path, 'r') as f:
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
        exit(1)

def save_match(private_key, hash_value):
    """Save matched private key and hash to a file."""
    with open("found.txt", "a") as f:
        f.write(f"Private Key: {private_key.hex()}\nRIPEMD-160 Hash: {hash_value}\n\n")

def generate_jump_table(size=100):
    """Generate jump table for the kangaroo algorithm with random steps."""
    return [os.urandom(32) for _ in range(size)]

def private_key_to_ripemd160(private_key):
    """Convert a private key to its RIPEMD-160 hash (both compressed and uncompressed)."""
    signing_key = SigningKey.from_string(private_key, curve=SECP256k1)
    public_key = signing_key.verifying_key.to_string()

    # Compress the public key based on y-coordinate parity
    compressed_key = b'\x02' + public_key[:32] if public_key[32] % 2 == 0 else b'\x03' + public_key[:32]
    uncompressed_key = b'\x04' + public_key

    ripemd160_compressed = hashlib.new('ripemd160', hashlib.sha256(compressed_key).digest()).digest()
    ripemd160_uncompressed = hashlib.new('ripemd160', hashlib.sha256(uncompressed_key).digest()).digest()

    return ripemd160_compressed.hex(), ripemd160_uncompressed.hex()

def kangaroo_jump(private_key, jump_table, index):
    """Perform a kangaroo jump based on the jump table at a given index."""
    step = int.from_bytes(jump_table[index % len(jump_table)], 'big')
    new_key = (int.from_bytes(private_key, 'big') + step) % SECP256K1_ORDER
    return new_key.to_bytes(32, 'big')

def scan_worker(start_key, end_key, targets, jump_table, stop_event, generated_count, lock):
    """Worker function to generate and check private keys using kangaroo jumps within a specified range."""
    current_key = start_key
    jump_index = 0

    while int.from_bytes(current_key, 'big') < int.from_bytes(end_key, 'big') and not stop_event.is_set():
        compressed, uncompressed = private_key_to_ripemd160(current_key)

        # Check if either hash matches the target
        if compressed in targets or uncompressed in targets:
            with lock:
                print(f"\nMatch found!\nPrivate Key: {current_key.hex()}\nRIPEMD-160 Hash: {compressed if compressed in targets else uncompressed}")
            save_match(current_key, compressed if compressed in targets else uncompressed)
            stop_event.set()
            break

        # Perform kangaroo jump and update state
        current_key = kangaroo_jump(current_key, jump_table, jump_index)
        jump_index += 1

        # Increment generated count
        with lock:
            generated_count.value += 1

def display_statistics(generated_count, start_time, stop_event):
    """Display statistics such as total keys generated and generation speed."""
    while not stop_event.is_set():
        time.sleep(1)
        elapsed_time = time.time() - start_time
        with generated_count.get_lock():
            total_keys = generated_count.value
        keys_per_second = total_keys / elapsed_time if elapsed_time > 0 else 0
        print(f"\r[Total keys generated: {total_keys}][Speed: {keys_per_second:.2f} Keys/s]", end="", flush=True)

def scan_keys(target_file, start_key, end_key):
    """Main function to start the kangaroo algorithm across multiple processes within specified key ranges."""
    targets = load_targets(target_file)
    generated_count = Value('i', 0)
    lock = Lock()
    stop_event = Event()
    jump_table = generate_jump_table(size=100)
    num_workers = cpu_count()

    # Calculate ranges for each worker
    ranges = [(start_key + i * (end_key - start_key) // num_workers, start_key + (i + 1) * (end_key - start_key) // num_workers)
              for i in range(num_workers)]
    
    start_time = time.time()

    # Statistics process
    stats_process = Process(target=display_statistics, args=(generated_count, start_time, stop_event))
    stats_process.start()

    # Launch worker processes for parallel scanning within specified ranges
    process_list = []
    for range_start, range_end in ranges:
        process = Process(
            target=scan_worker,
            args=(range_start.to_bytes(32, 'big'), range_end.to_bytes(32, 'big'), targets, jump_table, stop_event, generated_count, lock)
        )
        process.daemon = True
        process.start()
        process_list.append(process)

    # Wait for all processes to complete
    for process in process_list:
        process.join()

    # Stop the statistics process and print final count
    stop_event.set()
    stats_process.join()
    print(f"\nFinal total keys generated: {generated_count.value}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kangaroo Algorithm for Private Key Search")
    parser.add_argument("-f", "--file", required=True, help="Path to the target file containing RIPEMD-160 hashes.")
    args = parser.parse_args()

    # User-defined start and end range for key generation
    start_hex = input("Enter start of range (hex): ")
    end_hex = input("Enter end of range (hex): ")
    start_key = int(start_hex, 16)
    end_key = int(end_hex, 16)

    # Start scanning keys within the defined range
    scan_keys(args.file, start_key, end_key)
