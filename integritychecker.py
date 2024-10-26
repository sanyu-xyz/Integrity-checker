import hashlib
import os

# Function to compute hash of a file (SHA-256)
def compute_hash(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as file:
            while chunk := file.read(4096):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None

# Function to save the hash to a file
def save_hash(hash_value, hash_file):
    with open(hash_file, 'w') as f:
        f.write(hash_value)
    print(f"Hash saved to {hash_file}")

# Function to check integrity by comparing stored hash with current file hash
def check_integrity(file_path, hash_file):
    try:
        with open(hash_file, 'r') as f:
            stored_hash = f.read().strip()
    except FileNotFoundError:
        print(f"Hash file not found: {hash_file}")
        return

    current_hash = compute_hash(file_path)
    if current_hash == stored_hash:
        print(f"Integrity Check Passed: {file_path}")
    else:
        print(f"Integrity Check Failed: {file_path}")
        print(f"Stored Hash: {stored_hash}")
        print(f"Current Hash: {current_hash}")

# Main functionality
def integrity_checker():
    print("1. Compute and save hash")
    print("2. Check file integrity")
    choice = input("Enter choice (1/2): ")

    if choice == '1':
        file_path = input("Enter file path to compute hash: ")
        hash_value = compute_hash(file_path)
        if hash_value:
            hash_file = file_path + ".hash"
            save_hash(hash_value, hash_file)
    elif choice == '2':
        file_path = input("Enter file path to check integrity: ")
        hash_file = file_path + ".hash"
        check_integrity(file_path, hash_file)
    else:
        print("Invalid choice")

if __name__ == "__main__":
    integrity_checker()
