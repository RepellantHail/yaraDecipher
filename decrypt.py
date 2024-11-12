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

# Main brute-force function for RC4 with direct YARA validation
def brute_force_rc4_with_yara(ciphertext, yara_rules, max_key_length=6):
    print("Brute-force search started with YARA rule validation...")
    start_time = time.time()
    attempts = 0

    for length in range(1, max_key_length + 1):
        for key in generate_keys(length):
            attempts += 1
            decrypted_content = try_decrypt_rc4(ciphertext, key)

            # Use YARA rule to check decrypted content
            if decrypted_content and yara_rules.match(data=decrypted_content):
                total_time = time.time() - start_time
                print(f"Decryption successful with key: {key.decode()}")
                print(f"Total attempts: {attempts}")
                print(f"Total time taken: {total_time:.2f} seconds")
                return decrypted_content, key

    print("No valid key found.")
    print(f"Total attempts: {attempts}")
    return None, None

# Load encrypted data
with open("ciphered.txt", "rb") as f:
    ciphertext = f.read()

# Compile YARA rules
yara_rules = load_yara_rules("rules.yar")

# Start brute-force process with YARA rule validation
decrypted_content, found_key = brute_force_rc4_with_yara(ciphertext, yara_rules)

if decrypted_content:
    print("Decrypted Content:", decrypted_content.decode(errors="ignore"))
else:
    print("Failed to decrypt.")
