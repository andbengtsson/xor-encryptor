"""
Simple CLI tool for XOR-encrypting shellcode.

Reads raw bytes from a file, applies XOR with a chosen key,
and outputs the result in raw, Python or C format.

Author: Andreas Bengtsson
"""

import argparse
import time


def print_banner():
    """Print a simple ASCII banner"""
    print(r"""
========================================
      XOR SHELLCODE ENCRYPTOR (CLI)
        Author: Andreas Bengtsson
========================================
""")


def xor_encrypt(data: bytes, key: bytes) -> bytes:
    """
    XOR-encrypts input bytes using a repeating key.

    Loops through the data and XORs each byte with a byte from the key.
    If the key is shorter than the data, it repeats using modulo.

    Returns the encrypted bytes.

    """
    if not key:
        raise ValueError("Key must not be empty.")

    encrypted = bytearray()

    for i, byte_value in enumerate(data):
        encrypted.append(byte_value ^ key[i % len(key)])

    return bytes(encrypted)


def format_output(data: bytes, output_format: str) -> bytes:
    """
    Formats encrypted data into different outputs, like:
    raw     -> binary bytes that is written directy to file 
    python  -> list format that can be pasted into Python code
    c       -> unsigned char array for C programs

    """
    if output_format == "raw":
        return data

    if output_format == "python":
        result = "buf = [\n"
        for byte_value in data:
            result += f"    0x{byte_value:02x},\n"
        result += "]\n"
        return result.encode()

    if output_format == "c":
        result = "unsigned char buf[] = {\n"

        # Split output into rows of 12 bytes for readability
        bytes_per_line = 12
        for i in range(0, len(data), bytes_per_line):
            line_bytes = data[i:i + bytes_per_line]
            hex_values = ", ".join(f"0x{b:02x}" for b in line_bytes)

            # Add commas after each line except the last one
            if i + bytes_per_line < len(data):
                result += f"  {hex_values},\n"
            else:
                result += f"  {hex_values}\n"

        result += "};\n"
        return result.encode()

    raise ValueError(f"Unknown format: {output_format}")


def parse_key(key_string: str) -> bytes:
    """
    Parses the key provided by the user.

    If the key starts with 0x, it is treated as a single hex byte.
    Otherwise it is treated as text and encoded to bytes.

    Always returns the key as bytes so it can be used in XOR.
    """
    key_string = key_string.strip()

    if not key_string:
        raise ValueError("Key string is empty.")

    if key_string.startswith("0x"):
        key_value = int(key_string, 16)
        if not 0 <= key_value <= 0xFF:
            raise ValueError("Hex key must be a single byte (0x00 - 0xFF).")
        return bytes([key_value])

    key_bytes = key_string.encode()
    if not key_bytes:
        raise ValueError("Text key encoded to empty bytes.")
    return key_bytes


def encrypt_delay():
    """
    Small visual delay for the dots. 
    which makes it more fun to run it in the terminal. :)
    """
    print("[*] Encrypting shellcode", end="", flush=True)
    for _ in range(4):
        time.sleep(0.5)
        print(".", end="", flush=True)
    print()


def main():
    """
    Main entry point for the script.

    Handles CLI arguments, reads the input file, runs XOR encryption,
    formats the result and writes it to the output file.
    """
    print_banner()

    parser = argparse.ArgumentParser(
        description="XOR encryption of shellcode - produces raw/python/c output formats",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example usage:
  python xorcrypt.py --in shellcode.bin --out encrypted.bin --key 0x42 --format c
  python xorcrypt.py --in payload.bin   --out output.bin    --key "SecretKey" --format python
        """,
    )

    parser.add_argument(
        "-i", "--in",
        dest="input_file",
        required=True,
        help="Input file containing raw shellcode (binary file)",
    )
    parser.add_argument(
        "-o", "--out",
        dest="output_file",
        required=True,
        help="Output file for encrypted shellcode",
    )
    parser.add_argument(
        "-k", "--key",
        required=True,
        help="XOR key (hex single-byte e.g. 0x42, or text e.g. 'MyKey')",
    )
    parser.add_argument(
        "-f", "--format",
        choices=["raw", "python", "c"],
        default="raw",
        help="Output format: raw (binary), python (Python array), c (C array)",
    )

    args = parser.parse_args()

    # Step 1: Read input bytes from file
    print(f"[*] Reading shellcode from: {args.input_file}")
    try:
        with open(args.input_file, "rb") as f:
            shellcode = f.read()
        print(f"[+] Read {len(shellcode)} bytes")
    except FileNotFoundError:
        print(f"[!] Error: File not found: '{args.input_file}'")
        return
    except PermissionError:
        print(f"[!] Error: Permission denied when reading '{args.input_file}'")
        return
    except OSError as e:
        print(f"[!] OS error while reading file: {e}")
        return


    # Step 2: Parse key
    print(f"[*] Parsing key: {args.key}")
    try:
        key = parse_key(args.key)
    except ValueError as e:
        print(f"[!] Error: Invalid key: {e}")
        return
    print(f"[+] Key length: {len(key)} byte(s)")

    # Step 3: XOR-encrypt
    encrypt_delay()
    try:
        encrypted = xor_encrypt(shellcode, key)
    except ValueError as e:
        print(f"[!] Error during encryption: {e}")
        return
    print(f"[+] Encrypted {len(encrypted)} bytes")

    # Step 4: Format output
    print(f"[*] Formatting output as '{args.format}'...")
    try:
        formatted = format_output(encrypted, args.format)
    except ValueError as e:
        print(f"[!] Error: {e}")
        return

    # Step 5: Write output to file
    print(f"[*] Writing output to: {args.output_file}")
    try:
        with open(args.output_file, "wb") as f:
            f.write(formatted)
        print("[+] Done!")
    except PermissionError:
        print(f"[!] Error: Permission denied when writing '{args.output_file}'")
        return
    except OSError as e:
        print(f"[!] OS error while writing file: {e}")
        return


    # Summary
    print("\n=== Summary ===")
    print(f"Input file : {args.input_file}")
    print(f"Output file: {args.output_file}")
    print(f"Key        : {args.key}")
    print(f"Format     : {args.format}")
    print(f"Size       : {len(shellcode)} bytes -> {len(encrypted)} bytes")

    # Display output in terminal
    print("\n=== Encrypted Shellcode ===")
    if args.format == "raw":
        print("(Raw binary data - displayed as hexadecimal)")
        for i in range(0, len(encrypted), 16):
            hex_values = " ".join(f"{b:02x}" for b in encrypted[i:i + 16])
            print(f"  {hex_values}")
    else:
        print(formatted.decode(errors="replace"))
    print()


if __name__ == "__main__":
    main()
