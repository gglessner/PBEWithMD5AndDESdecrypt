"""
PBEWithMD5AndDES - Password-Based Encryption with MD5 and DES
Copyright (C) 2024 Garland Glessner <gglessner@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

from Crypto.Cipher import DES
from Crypto.Hash import MD5
from Crypto.Util.Padding import unpad
import base64
import sys
import time

def is_valid_plaintext(text):
    if text is None or len(text) < 3 or len(text) > 50:
        return False
    
    # Check if all characters are printable ASCII (space through tilde)
    for c in text:
        if ord(c) < 32 or ord(c) > 126:
            return False
    
    # Must have at least 50% alphanumeric
    alphanumeric_count = sum(1 for c in text if c.isalnum())
    return alphanumeric_count >= len(text) // 2

def derive_key_iv_pbe(password, salt, iteration_count):
    """
    Derive key and IV using PBE with MD5 (PKCS#5 style).
    
    Args:
        password (bytes): Password for derivation
        salt (bytes): Salt for derivation (8 bytes for DES)
        iteration_count (int): Number of iterations
        
    Returns:
        tuple: (key, iv) where key is 8 bytes for DES and iv is 8 bytes
    """
    # Concatenate password and salt
    data = password + salt
    
    # Apply MD5 hash iterations
    digest = data
    for _ in range(iteration_count):
        digest = MD5.new(digest).digest()
    
    # DES key is first 8 bytes, IV is next 8 bytes
    derived_key = digest[:8]
    derived_iv = digest[8:16]
    
    return derived_key, derived_iv

def main():
    # Get inputs
    salt_b64 = input("\nEnter the salt in base64 format (or press Enter to use brute force): ").strip()
    password = input("Enter the password/key: ").strip()
    ciphertext = input("Enter the ciphertext to decrypt: ").strip()
    
    # Check if user provided a salt
    user_salt = None
    if salt_b64:
        try:
            user_salt = base64.b64decode(salt_b64)
            print(f"\nUsing provided salt: {user_salt.hex()}")
            print("Testing only with provided salt and iteration range 1-5000...")
        except Exception:
            print("Invalid base64 salt, falling back to brute force discovery.")
            salt_b64 = ""
    
    if not salt_b64:
        print("\n=== Brute Force Iteration and Configuration Discovery ===")
        print("Testing iterations from 1 to 5000...")
        print("Configurations: Prepended salt (8 bytes), No salt (zero salt), Appended salt (8 bytes)")
    
    print(f"Password: {password}")
    print(f"Target: {ciphertext[:50]}...")
    print()
    
    valid_results = 0
    start_time = time.time()
    total_tests = 0
    
    try:
        full_bytes = base64.b64decode(ciphertext)
    except Exception:
        print("Invalid base64 ciphertext.")
        return
    
    password_bytes = password.encode('utf-8')
    
    for iterations in range(1, 5001):
        # If user provided a salt, only test with that salt
        if user_salt:
            configs_to_test = ["provided"]
        else:
            configs_to_test = ["prepended", "none", "appended"]
            
        for config in configs_to_test:
            total_tests += 1
            try:
                config_desc = ""
                to_decrypt = full_bytes
                salt = None
                
                if config == "provided":
                    config_desc = f"Provided salt (base64: {salt_b64})"
                    salt = user_salt
                    to_decrypt = full_bytes  # Use full ciphertext with provided salt
                elif config == "prepended":
                    config_desc = "Prepended salt (8 bytes)"
                    if len(full_bytes) < 16 or len(full_bytes) % 8 != 0:
                        continue
                    salt = full_bytes[:8]
                    to_decrypt = full_bytes[8:]
                elif config == "none":
                    config_desc = "No salt (fixed zero salt)"
                    salt = b'\x00' * 8
                elif config == "appended":
                    config_desc = "Appended salt (8 bytes)"
                    if len(full_bytes) < 16 or len(full_bytes) % 8 != 0:
                        continue
                    salt = full_bytes[-8:]
                    to_decrypt = full_bytes[:-8]

                
                # Derive key and IV
                derived_key, derived_iv = derive_key_iv_pbe(password_bytes, salt, iterations)
                
                # Create cipher (CBC mode)
                cipher = DES.new(derived_key, DES.MODE_CBC, derived_iv)
                
                # Decrypt
                dec_bytes_padded = cipher.decrypt(to_decrypt)
                
                # Unpad
                dec_bytes = unpad(dec_bytes_padded, DES.block_size)
                
                # Decode to UTF-8
                decrypted = dec_bytes.decode('utf-8')
                
                # Validate
                if is_valid_plaintext(decrypted):
                    valid_results += 1
                    elapsed = time.time() - start_time
                    
                    print()
                    print(f"*** VALID RESULT FOUND #{valid_results} ***")
                    print(f"Iterations: {iterations}")
                    print(f"Configuration: {config_desc}")
                    print(f"Decrypted text: '{decrypted}'")
                    print(f"Length: {len(decrypted)}")
                    print(f"Time taken: {elapsed:.1f} seconds")
                    print()
            except Exception:
                # Decryption failed for this configuration - continue silently
                pass
        
        # Progress update every 100 iterations
        if iterations % 100 == 0:
            elapsed = time.time() - start_time
            speed = total_tests / elapsed if elapsed > 0 else 0
            print(f"Progress: {iterations}/5000 iterations ({iterations / 5000 * 100:.1f}%) - Speed: {speed:.1f} tests/sec - Found: {valid_results} results")
    
    total_time = time.time() - start_time
    print()
    print("=== DISCOVERY COMPLETE ===")
    print("Total iterations tested: 5000")
    print("Total configurations per iteration: 3 (or 1 if salt provided)")
    print(f"Total tests performed: {total_tests}")
    print(f"Total valid results found: {valid_results}")
    print(f"Total time taken: {total_time:.1f} seconds")
    print(f"Average speed: {total_tests / total_time:.1f} tests/second" if total_time > 0 else "Average speed: N/A")
    
    if valid_results == 0:
        print()
        print("No valid plaintext found. This could mean:")
        print("1. Wrong password")
        print("2. Ciphertext is corrupted")
        print("3. Different algorithm/configuration used (e.g., different salt size, hex output, other fixed salt, etc.)")
        print("4. Iteration count is > 5000")
        print("5. Plaintext doesn't match validation criteria - adjust is_valid_plaintext if needed")
        print("6. For custom salt scenarios, ensure the correct salt is provided in base64 format")

if __name__ == "__main__":
    main()