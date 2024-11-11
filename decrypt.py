import yara
from arc4 import ARC4
from itertools import product
import string
import time

# Load YARA rule
def load_yara_rules(rule_path):
    return yara.compile(filepath=rule_path)

# Attempt decryption with RC4
def try_decrypt_rc4(ciphertext, key):
    try:
        cipher = ARC4(key)
        decrypted_data = cipher.decrypt(ciphertext)
        return decrypted_data
    except Exception:
        return None

# Generate possible keys (assuming alphanumeric keys)
def generate_keys(key_length):
    chars = string.ascii_letters + string.digits
    for key_tuple in product(chars, repeat=key_length):
        yield ''.join(key_tuple).encode('utf-8')

# Load the original plaintext file for comparison
def load_sample_file(sample_path):
    with open(sample_path, "rb") as f:
        return f.read()

# Main brute-force function for RC4 with direct content validation
def brute_force_rc4(ciphertext, sample_content, max_key_length=6):
    print("Brute-force search started...")
    start_time = time.time()
    attempts = 0
    last_length = 0  # Track the last key length (to highlight when it increases)

    for length in range(1, max_key_length + 1):
        for key in generate_keys(length):
            attempts += 1
            decrypted_content = try_decrypt_rc4(ciphertext, key)

            # Stop if the decrypted content matches the sample content
            if decrypted_content == sample_content:
                total_time = time.time() - start_time
                print(f"Decryption successful with key: {key.decode()}")
                print(f"Total attempts: {format_attempts(attempts)}")
                print(f"Total time taken: {total_time:.2f} seconds")
                return decrypted_content, key

    print("No valid key found.")
    print(f"Total attempts: {format_attempts(attempts)}")
    return None, None

# Helper function to format attempts
def format_attempts(attempts):
    return f"{attempts:,}".replace(",", " ")

# Load encrypted data
with open("ciphered.txt", "rb") as f:
    ciphertext = f.read()

# Load sample plaintext data for comparison
sample_content = load_sample_file("sample.txt")

# Start brute-force process
decrypted_content, found_key = brute_force_rc4(ciphertext, sample_content)

if decrypted_content:
    print("Decrypted Content:", decrypted_content.decode(errors="ignore"))
else:
    print("Failed to decrypt.")
