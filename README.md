# WSU-Crypt - CS427 Security

## Contact

Author: Jason Willmore

Email: jasonwillmore@wsu.edu

## Description

A program for the block-encryption algorithm called WSU-CRYPT (based on Twofish by Bruce Schneier, John Kelsey, Doug Whiting, David Wagner, Chris Hall and SKIPJACK by the NSA combined). This program was created for CS427 at Washington State University Vancouver. WSU-CRYPT is implemented using a 64 bit block size and a 64 bit key.

## Build It

WSU-Crypt runs in Python 3. To run it just enter the following into the terminal of a computer with python 3 installed.

```bash
python3 wsu-crypt.py
```

## Run It

Most terminal output is turned off through the use of two flags.
DEBUG output describes most things happening during the encryption and decryption process
VERBOSE output creates output similar to the testVectors.txt given to us in class
These both will need to be set to True to get all output.

```python
DEBUG = False
VERBOSE = False
```

Place something to be encrypted and decrypted into "plaintext.txt". It will be encrypted and written to ciphertext.txt. The program will then pull the text from "ciphertext.txt" and decrypt it and write that back to "plaintext.txt" If the program works then "plaintext.txt" should look the same before and after the program runs.

## Files Included

- README.md: A markdown version of the readme file for the program
- key.txt: Stores the key which the decryption program uses.
- plaintext.txt: Stores the text which will be encrypted and the output of a decryption.
- ciphertext.txt: Stores the output ciphertext in hexademical from an encryption.