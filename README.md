<p align="center">
  <img src="assets/xor-encryptor-banner.png" width="100%">
</p>


# XOR Shellcode Encryptor (Python CLI)

A small Python CLI tool that reads raw bytes from a file, applies XOR
with a user-defined key, and writes the result to a new file.

The output can be saved as: - raw binary - Python list format - C
unsigned char array

This project was created as part of a school assignment in IT security.

------------------------------------------------------------------------

## What the script does

1.  Reads input data as raw bytes from a file\
2.  Parses a key from the command line\
3.  Applies XOR byte-by-byte using a repeating key\
4.  Formats the result based on the chosen output format\
5.  Writes the result to a file

The script does **not decrypt** anything.\
It only prepares encrypted/obfuscated shellcode.

------------------------------------------------------------------------

## Requirements

-   Python 3.10+\
-   No external libraries (standard library only)

------------------------------------------------------------------------

## File structure

    xor-encryptor/
    │
    ├─ xorcrypt.py
    ├─ README.md
    ├─ .gitignore
    └─ examples/
       ├─ input.bin
       ├─ output.c.txt
       └─ output.py.txt
    

------------------------------------------------------------------------

## Usage

The CLI supports both short and long flags.

Show help:

``` bash
python xorcrypt.py -h
```

Basic command structure:
``` bash
python xorcrypt.py --in <input_file> --out <output_file> --key <key> --format <format>
```
```bash
python xorcrypt.py -i shellcode.bin -o encrypted.bin -k 0x42 -f c
```

Arguments:

  -----------------------------------------------------------------------


| Short | Long       | Description                                                      |
| ----- | ---------- | ---------------------------------------------------------------- |
| `-i`  | `--in`     | Input file containing raw bytes                                  |
| `-o`  | `--out`    | Output file for encrypted data                                   |
| `-k`  | `--key`    | XOR key (hex single byte like `0x42` or text like `"SecretKey"`) |
| `-f`  | `--format` | Output format: `raw`, `python`, or `c`                           |



## Examples

### 1) Raw binary output

``` bash
python xorcrypt.py --in examples/input.bin --out encrypted.bin --key 0x42 --format raw
```

This writes encrypted bytes directly to `encrypted.bin`.

------------------------------------------------------------------------

### 2) C array output

``` bash
python xorcrypt.py --in examples/input.bin --out examples/output.c.txt --key 0x42 --format c
```

Example output:

``` c
unsigned char buf[] = {
  0x12, 0xa1, 0x4f
};
```

------------------------------------------------------------------------

### 3) Python array output

``` bash
python xorcrypt.py --in examples/input.bin --out examples/output.py.txt --key "SecretKey" --format python
```

Example output:

``` python
buf = [
    0x12,
    0xa1,
    0x4f,
]
```

------------------------------------------------------------------------

## Key handling

The script supports two types of keys:

### Hex key (single byte)

Example:

    0x42

This is parsed as one byte (0x00--0xFF).

------------------------------------------------------------------------

### Text key (multi-byte)

Example:

    SecretKey

Each character becomes a byte, and the key repeats during XOR.

------------------------------------------------------------------------

## How the XOR works

For each byte in the input file:

    encrypted_byte = input_byte XOR key[i % len(key)]

This means: - the key repeats if it is shorter than the input - output
length is always the same as input length

------------------------------------------------------------------------

## Output formats

### raw

Writes encrypted bytes directly to file.

### python

Creates a Python list of hex values.

### c

Creates a formatted unsigned char array suitable for C loaders.

------------------------------------------------------------------------

## Example workflow

1.  Prepare an input file with raw bytes\
2.  Choose a key\
3.  Run the script\
4.  Use the output in another tool or loader

------------------------------------------------------------------------

## Notes

-   This tool uses XOR for **obfuscation**, not secure encryption.\
-   The goal is to transform byte sequences and output them in useful
    formats.\
-   Designed for learning purposes and demonstration.

------------------------------------------------------------------------

## Author

Andreas Bengtsson\
IT Security student (IT-Högskolan)

------------------------------------------------------------------------

## License

No license, this is only for educational use.