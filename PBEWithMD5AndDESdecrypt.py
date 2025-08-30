#!/usr/bin/env python3

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
import signal
import argparse

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

def is_hex_string(text):
    """Check if a string contains only hexadecimal characters."""
    if not text:
        return False
    return all(c in '0123456789abcdefABCDEF' for c in text)

def hex_to_bytes(hex_string):
    """Convert a hexadecimal string to bytes."""
    # Remove any '0x' prefix if present
    if hex_string.startswith('0x'):
        hex_string = hex_string[2:]
    # Ensure even length by padding with leading zero if needed
    if len(hex_string) % 2 != 0:
        hex_string = '0' + hex_string
    return bytes.fromhex(hex_string)

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
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="PBE with MD5 and DES decryption tool - Decrypts data encrypted with Password-Based Encryption using MD5 and DES",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -p "mypassword" -c "base64ciphertext"
  %(prog)s -s "b64salt" -p "mypassword" -c "base64ciphertext"
  %(prog)s --password "mypassword" --ciphertext "base64ciphertext" --brute-force
  %(prog)s  # (interactive mode - no arguments)
        """
    )
    parser.add_argument('-V', '--version', action='version', version='%(prog)s 1.0')
    parser.add_argument('-s', '--salt', 
                       help='Base64-encoded salt (optional, will use brute force if not provided)')
    parser.add_argument('-p', '--password', 
                       help='Password/key for decryption')
    parser.add_argument('-c', '--ciphertext', 
                       help='Base64-encoded ciphertext to decrypt')
    parser.add_argument('-i', '--iterations', type=int, metavar='N',
                       help='Fixed iteration count (1-5000, skips brute force discovery)')
    parser.add_argument('--brute-force', action='store_true',
                       help='Force brute force mode even if salt is provided')
    
    args = parser.parse_args()
    
    # Validate iterations argument if provided
    if args.iterations is not None:
        if args.iterations < 1 or args.iterations > 5000:
            print("Error: Iterations must be between 1 and 5000.")
            return
    
    # Check if required arguments are provided
    if not args.password or not args.ciphertext:
        print("No command line arguments provided. Switching to interactive mode...")
        print()
        # Fall back to interactive input
        salt_b64 = input("Enter the salt in base64 format (or press Enter to use brute force): ").strip()
        password = input("Enter the password/key: ").strip()
        ciphertext = input("Enter the ciphertext to decrypt: ").strip()
        
        # Validate interactive inputs
        if not password or not ciphertext:
            print("Error: Password and ciphertext are required.")
            return
    else:
        # Use command line arguments
        salt_b64 = args.salt
        password = args.password
        ciphertext = args.ciphertext
        
        # If salt is provided but brute force is requested, clear the salt
        if args.brute_force and salt_b64:
            print("\n[!] Brute force mode requested - ignoring provided salt")
            salt_b64 = None
    
    # Flag to track if user interrupted the process
    interrupted = False
    
    def signal_handler(signum, frame):
        nonlocal interrupted
        interrupted = True
        print("\n\n[!] Interrupted by user (Ctrl+C)")
        print("[!] Finishing current iteration and exiting gracefully...")
    
    # Set up signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    

    
    # Check if user provided a salt and decode it if present
    user_salt = None
    if salt_b64:
        try:
            # Check if salt is hexadecimal
            if is_hex_string(salt_b64):
                user_salt = hex_to_bytes(salt_b64)
                print(f"\nUsing provided hexadecimal salt: {user_salt.hex()}")
            else:
                # Try base64 decode
                user_salt = base64.b64decode(salt_b64)
                print(f"\nUsing provided base64 salt: {user_salt.hex()}")
        except Exception:
            print("Invalid salt format, falling back to brute force discovery.")
            salt_b64 = ""
            user_salt = None
    
    # Determine iteration range and mode
    if args.iterations is not None:
        # Fixed iteration mode
        iteration_range = [args.iterations]
        print(f"\n=== Fixed Iteration Mode ===")
        print(f"Testing with fixed iteration count: {args.iterations}")
        if user_salt:
            print("Testing only with provided salt...")
        else:
            print("Testing configurations: Prepended salt (8 bytes), No salt (zero salt), Appended salt (8 bytes)")
    else:
        # Brute force mode - try 1000 first, then brute force
        if user_salt:
            print("Testing only with provided salt and iteration range 1-5000...")
            # Try 1000 first, then brute force
            iteration_range = [1000] + list(range(1, 5001))
        else:
            print("\n=== Brute Force Iteration and Configuration Discovery ===")
            print("Testing iterations: 1000 (default) first, then 1-5000...")
            print("Configurations: Prepended salt (8 bytes), No salt (zero salt), Appended salt (8 bytes)")
            # Try 1000 first, then brute force
            iteration_range = [1000] + list(range(1, 5001))
    
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
    
    for iterations in iteration_range:
        # Check if user interrupted the process
        if interrupted:
            print(f"\n[!] Stopped at iteration {iterations-1}")
            break
            
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
                    
                    # Stop after first valid result found
                    print("Password found! Exiting...")
                    return
            except Exception:
                # Decryption failed for this configuration - continue silently
                pass
        
        # Progress update every 100 iterations (only in brute force mode)
        if args.iterations is None and iterations % 100 == 0 and iterations > 1000:
            elapsed = time.time() - start_time
            speed = total_tests / elapsed if elapsed > 0 else 0
            print(f"Progress: {iterations}/5000 iterations ({iterations / 5000 * 100:.1f}%) - Speed: {speed:.1f} tests/sec - Found: {valid_results} results")
    
    total_time = time.time() - start_time
    print()
    
    if args.iterations is not None:
        # Fixed iteration mode summary
        print("=== FIXED ITERATION MODE COMPLETE ===")
        print(f"Fixed iteration count: {args.iterations}")
    elif interrupted:
        print("=== DISCOVERY INTERRUPTED ===")
        print(f"Total iterations tested: {iterations-1}")
    else:
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