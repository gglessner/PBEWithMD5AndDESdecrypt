# PBEWithMD5AndDESdecrypt

A Python tool for decrypting data encrypted with Password-Based Encryption (PBE) using MD5 and DES algorithms. This tool can automatically discover encryption parameters and decrypt ciphertext when the password is known.

## Description

This tool implements PBE with MD5 and DES as used in Jasypt and similar encryption libraries. It uses PBKDF1-MD5 to derive encryption keys and can handle various salt configurations:

- **Prepended salt**: 8-byte salt at the beginning of ciphertext
- **Appended salt**: 8-byte salt at the end of ciphertext  
- **No salt**: Fixed zero salt
- **Custom salt**: User-provided salt in base64 format

## Features

- Automatic parameter discovery (iteration count, salt position)
- Support for multiple salt configurations
- Brute force iteration testing (1-5000 iterations)
- Validation of decrypted plaintext
- Progress tracking and performance metrics
- Base64 input/output support

## Installation

1. Clone or download this repository
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Interactive Mode
Run the script without arguments and follow the prompts:

```bash
python PBEWithMD5AndDESdecrypt.py
```

### Command Line Mode
Pass arguments directly for automated/scripted use:

```bash
# Basic usage with password and ciphertext
python PBEWithMD5AndDESdecrypt.py -p "mypassword" -c "base64ciphertext"

# With specific salt
python PBEWithMD5AndDESdecrypt.py -s "b64salt" -p "mypassword" -c "base64ciphertext"

# With fixed iteration count (skips brute force)
python PBEWithMD5AndDESdecrypt.py -i 1000 -p "mypassword" -c "base64ciphertext"

# Force brute force mode (ignores provided salt)
python PBEWithMD5AndDESdecrypt.py -s "b64salt" -p "mypassword" -c "base64ciphertext" --brute-force

# Show help
python PBEWithMD5AndDESdecrypt.py -h

# Show version
python PBEWithMD5AndDESdecrypt.py -V
```

### Command Line Options

- `-s, --salt`: Base64-encoded salt (optional, will use brute force if not provided)
- `-p, --password`: Password/key for decryption (required)
- `-c, --ciphertext`: Base64-encoded ciphertext to decrypt (required)
- `-i, --iterations N`: Fixed iteration count (1-5000, skips brute force discovery)
- `--brute-force`: Force brute force mode even if salt is provided
- `-h, --help`: Show help message
- `-V, --version`: Show version information

### Modes of Operation

- **Interactive Mode**: Run without arguments for interactive prompts
- **Command Line Mode**: Pass arguments for automated/scripted use
- **Brute Force Mode**: Test iterations 1-5000 to discover encryption parameters
- **Fixed Iteration Mode**: Test with a specific iteration count (use `-i` option)

### Input Parameters

1. **Salt** (optional): Base64-encoded salt, or press Enter for brute force discovery
2. **Password**: The encryption password/key
3. **Ciphertext**: Base64-encoded encrypted data
4. **Iterations** (optional): Fixed iteration count when known

### Example Session

```
Enter the salt in base64 format (or press Enter to use brute force discovery): 
Enter the password/key: abc
Enter the ciphertext to decrypt: 5hnCuGuxUo7kjXQ+YwB3WmlUzh3QHq+S

=== Brute Force Iteration and Configuration Discovery ===
Testing iterations from 1 to 5000...
Configurations: Prepended salt (8 bytes), No salt (zero salt), Appended salt (8 bytes)
Password: abc
Target: 5hnCuGuxUo7kjXQ+YwB3WmlUzh3QHq+S...

*** VALID RESULT FOUND #1 ***
Iterations: 1000
Configuration: Prepended salt (8 bytes)
Decrypted text: 'thisisatest'
Length: 12
Time taken: 0.1 seconds
```

## Technical Details

### Algorithm
- **Encryption**: DES-CBC mode with PKCS5 padding
- **Key Derivation**: PBKDF1-MD5 (PKCS#5 style)
- **Salt Size**: 8 bytes
- **Key Size**: 8 bytes (DES requirement)
- **IV Size**: 8 bytes
- **Iterations**: Configurable (typically 1000)

### Key Derivation Process
1. Concatenate password and salt
2. Apply MD5 hash iteratively (specified iteration count)
3. First 8 bytes become DES key
4. Next 8 bytes become DES IV

### Salt Configurations
- **Prepended**: Salt is first 8 bytes of ciphertext
- **Appended**: Salt is last 8 bytes of ciphertext
- **None**: Uses 8 bytes of zeros as salt
- **Custom**: User-provided salt (base64 encoded)

## Output

The tool provides:
- Valid decryption results with parameters
- Progress updates every 100 iterations
- Performance metrics (tests/second)
- Summary of total tests performed
- Time taken for discovery

## Validation

Decrypted text is validated using these criteria:
- Length between 3-50 characters
- All characters are printable ASCII (32-126)
- At least 50% alphanumeric characters

## Performance

Typical performance on modern hardware:
- ~1000-5000 tests/second depending on system
- Full 5000 iteration test completes in 1-5 seconds
- Progress updates every 100 iterations

## Use Cases

- Recovering data from Jasypt-encrypted files
- Testing PBE encryption implementations
- Security research and analysis
- Legacy system data recovery

## License

This project is licensed under the GNU General Public License v3.0 - see the license header in the source code for details.

## Author

Garland Glessner <gglessner@gmail.com>

## Dependencies

- **pycryptodome**: Provides DES cipher, MD5 hash, and padding utilities
- **Python 3.6+**: For f-string support and modern Python features

## Troubleshooting

### Common Issues

1. **"Invalid base64 ciphertext"**: Ensure ciphertext is properly base64 encoded
2. **"No valid plaintext found"**: 
   - Check password correctness
   - Verify ciphertext format
   - Consider different salt configurations
   - Iteration count may exceed 5000

### Performance Tips

- Use specific salt when known (faster than brute force)
- For large iteration counts, consider increasing the range in the code
- Monitor system resources during long-running tests

## Contributing

Contributions are welcome! Please ensure any modifications maintain compatibility with the existing PBE standard and include appropriate testing.
