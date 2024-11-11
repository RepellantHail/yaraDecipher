# yaraDecipher
This project uses RC4 encryption to encrypt a file with a passkey, then decrypts it using a brute-force approach. YARA rules are employed to detect the passkey from the ciphertext.

Step 1: Compile and Run the RC4 Program
Compile the C++ program:

bash
Copiar código
g++ rc4_program.cpp -o rc4_program
Run the program:

bash
Copiar código
./rc4_program
Enter the Passkey when prompted. The program encrypts sample.txt and outputs the encrypted file as ciphered.txt.

Step 2: YARA Rule Analysis
Ensure YARA is installed. Run the YARA rule to detect the passkey in ciphered.txt:

bash
Copiar código
yara Detect_RC4_Encrypted_File rules.yar ciphered.txt
Step 3: Brute Force Decryption
Install Python dependencies:

bash
Copiar código
pip install yara-python
Run the brute-force script:

bash
Copiar código
python decrypt.py
The script tries all key combinations, using YARA to detect the correct passkey and stop once the correct one is found.

File Breakdown
rc4_program.cpp: Encrypts sample.txt with the passkey.
decrypt.py: Brute-forces the passkey, comparing each attempt to sample.txt.
rules.yar: YARA rule that detects the passkey in ciphered.txt.
sample.txt: The original plaintext.
ciphered.txt: The encrypted file.
deciphered.txt: The output after successful decryption.
Notes:

The brute-force process may take time based on key complexity.
YARA is used to detect the encrypted passkey in the ciphertext.
