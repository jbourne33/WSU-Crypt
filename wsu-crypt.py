PLAINTEXT_FILENAME = "plaintext.txt"
CIPHERTEXT_FILENAME = "ciphertext.txt"
KEY_FILENAME = "key.txt"
KEY = 0
ENCRYPTION = True
DEBUG = True
VERBOSE = True


f_table = [0xa3,0xd7,0x09,0x83,0xf8,0x48,0xf6,0xf4,0xb3, 0x21,0x15,0x78,0x99,0xb1,0xaf,0xf9, 0xe7,0x2d,0x4d,0x8a,0xce,0x4c,0xca,0x2e,0x52,0x95,0xd9,0x1e,0x4e,0x38,0x44,0x28, 0x0a,0xdf,0x02,0xa0,0x17,0xf1,0x60,0x68,0x12,0xb7,0x7a,0xc3,0xe9,0xfa,0x3d,0x53,0x96,0x84,0x6b,0xba,0xf2,0x63,0x9a,0x19,0x7c,0xae,0xe5,0xf5,0xf7,0x16,0x6a,0xa2,0x39,0xb6,0x7b,0x0f,0xc1,0x93,0x81,0x1b,0xee,0xb4,0x1a,0xea,0xd0,0x91,0x2f,0xb8, 0x55,0xb9,0xda,0x85,0x3f,0x41,0xbf,0xe0,0x5a,0x58,0x80,0x5f,0x66,0x0b,0xd8,0x90, 0x35,0xd5,0xc0,0xa7,0x33,0x06,0x65,0x69,0x45,0x00,0x94,0x56,0x6d,0x98,0x9b,0x76, 0x97,0xfc,0xb2,0xc2,0xb0,0xfe,0xdb,0x20,0xe1,0xeb,0xd6,0xe4,0xdd,0x47,0x4a,0x1d, 0x42,0xed,0x9e,0x6e,0x49,0x3c,0xcd,0x43,0x27,0xd2,0x07,0xd4,0xde,0xc7,0x67,0x18, 0x89,0xcb,0x30,0x1f,0x8d,0xc6,0x8f,0xaa,0xc8,0x74,0xdc,0xc9,0x5d,0x5c,0x31,0xa4, 0x70,0x88,0x61,0x2c,0x9f,0x0d,0x2b,0x87,0x50,0x82,0x54,0x64,0x26,0x7d,0x03,0x40, 0x34,0x4b,0x1c,0x73,0xd1,0xc4,0xfd,0x3b,0xcc,0xfb,0x7f,0xab,0xe6,0x3e,0x5b,0xa5, 0xad,0x04,0x23,0x9c,0x14,0x51,0x22,0xf0,0x29,0x79,0x71,0x7e,0xff,0x8c,0x0e,0xe2, 0x0c,0xef,0xbc,0x72,0x75,0x6f,0x37,0xa1,0xec,0xd3,0x8e,0x62,0x8b,0x86,0x10,0xe8, 0x08,0x77,0x11,0xbe,0x92,0x4f,0x24,0xc5,0x32,0x36,0x9d,0xcf,0xf3,0xa6,0xbb,0xac, 0x5e,0x6c,0xa9,0x13,0x57,0x25,0xb5,0xe3,0xbd,0xa8,0x3a,0x01,0x05,0x59,0x2a,0x46]


def add_pad(pad_num, str_leftover):
    """
    Pads out a string with a certain amount of zeros till it is a desired length.
    - parameter int_pad: The number of characters to add to the string.
    - parameter str_leftover: The string to append the padding to.
    - returns: The padded string
    """
    for i in range(pad_num):
        str_leftover += '0'
    return str_leftover


def ascii_to_hex(string):
    # converts a string value to an integer which will be treated like a hex value
    val = 0
    for i in string:
        val = val << 8 | ord(i)
    return val


def ascii_to_hex_blocks(string_array):
    # returns an array of hex values from an array of strings
    hex_array = []
    for chunk in string_array:
        hex_val = ascii_to_hex(chunk)
        hex_array.append(hex_val)
    return hex_array


def hex_to_ascii(hex):
    # converts a 64bit integer or hex value as a string in ascii format
    plaintext = ''
    for i in range(7, -1, -1):
        b = hex >> (8*i) & 0xff
        if(chr(b) != '0'):
            plaintext = plaintext + chr(b)
    return plaintext


def chunk_plaintext(plaintext_str, bit=8):
    # takes a string of any size and breaks it into 64 bit chunks with padding on last chunk if needed.
    chunks = []
    plaintext_length = len(plaintext_str)
    for i in range(0, plaintext_length, bit):
        if (i+bit <= plaintext_length):
            chunks.append(plaintext_str[i : i+bit])
        else:
            leftover_count = plaintext_length - i
            leftover = plaintext_str[i : plaintext_length]
            chunks.append(add_pad(bit-leftover_count, leftover))
    return chunks


def get_plaintext_input_as_hex_blocks():
    # Takes a standard ASCII file named 'plaintext.txt' as input and returns the contents as 64 bit blocks of hex
    with open(PLAINTEXT_FILENAME) as f:
        input_text = f.read()
    if VERBOSE: print("Plaintext input:", input_text)
    blocks = chunk_plaintext(input_text)
    if DEBUG: print("plaintext blocks:", blocks)
    hex_blocks = ascii_to_hex_blocks(blocks)
    if DEBUG: print("hex_blocks from plaintext:", hex_blocks)
    return hex_blocks


def get_ciphertext_input_chunks():
    # Takes a standard ascii file named 'ciphertext.txt' as input 
    with open(CIPHERTEXT_FILENAME) as f:
        input_ciphertext = f.read()
    if VERBOSE: print("raw Ciphertext input:", input_ciphertext)
    if input_ciphertext[0] is not None and input_ciphertext[0] == '0' and input_ciphertext[1] is not None and input_ciphertext[1] == 'x':
        input_ciphertext = input_ciphertext[2:]
        if DEBUG: print("'0x' marker preceding ciphertext input")
    if DEBUG: print(input_ciphertext)
    ciphertext_chunks = chunk_plaintext(input_ciphertext, 16)
    ciphertext_hex_chunks = []
    for chunk in ciphertext_chunks:
        hex_chunk = hex_string_to_hex(chunk)
        ciphertext_hex_chunks.append(hex_chunk)
    if DEBUG: print("ciphertext hex chunks:", ciphertext_hex_chunks)
    return ciphertext_hex_chunks


def hex_to_hex_quarters(hex_val):
    # Takes a 64 bit hex value and returns four 16 bit sections.
    a3 = hex_val & 0xffff
    a2 = (hex_val >> 16) & 0xffff
    a1 = (hex_val >> 32) & 0xffff
    a0 = (hex_val >> 48) & 0xffff
    return (a0, a1, a2, a3)


def hex_string_to_hex(text, type = 16):
    # This method is specifically meant to take in an ascii representation of hex
    val = int(text, type)  # '16' assumes there is no 0x at the beginning of the hex string
    return val


def read_key():
    # Reads in the key from key.txt and stores it in global variable KEY
    global KEY 
    with open(KEY_FILENAME) as f:
        ascii_key = f.read()
        if DEBUG: print("ascii_key:", ascii_key)
    if ascii_key[0] is not None and ascii_key[0] == '0' and ascii_key[1] is not None and ascii_key[1] == 'x':
        if DEBUG: print("'0x' marker preceding key")
        KEY = hex_string_to_hex(ascii_key, 0)
    else:
        if DEBUG: print("no hex marker preceding key")
        KEY = hex_string_to_hex(ascii_key)


def file_output(hex_output):
    """
    Encryption: Returns a HEX file called 'ciphertext.txt' which is the encryption of the input file under WSU-CRYPT.
    Decryption: Returns a HEX file called 'plaintext.txt' which is the decryption of the input file under WSU-CRYPT.
    """
    direction = ""
    filename = ""
    if ENCRYPTION:  # Encrypting
        direction = "encrypted ciphertext"
        filename = CIPHERTEXT_FILENAME
        with open(filename, "w") as f:
            f.write('{:016x}'.format(hex_output))
    else:  # Decrypting
        direction = "decrypted plaintext"
        filename = PLAINTEXT_FILENAME
        with open(filename, "w") as f:
            f.write(hex_output)
    print("writing", direction, "to", filename)


def concatenate_two_hexes(a, b, bit = 8):
    # concatenates two hexadecimal values
    return a << bit | b


MASK = (1 << 64) - 1
def left_rotate_key():
    key = ((KEY << 1) & MASK)| KEY >> 64-1
    return key
    
def right_rotate_key():
    key = KEY >> 1| ((KEY << 64-1) & MASK)
    return key


def K(x):
    global KEY
    chunk = x%8
    if ENCRYPTION:  # Encrypting
        KEY = left_rotate_key()
        segment = KEY >> (chunk * 8) & 0xff
        return segment
    else:  # Decrypting
        segment = KEY >> (chunk * 8) & 0xff
        KEY = right_rotate_key()
        return segment


def G(w, key1, key2, key3, key4):
    if DEBUG: print("w:", hex(w))
    g1 = (w >> 8) & 0xff
    g2 = w & 0xff
    g3 = f_table[g2 ^ key1] ^ g1
    g4 = f_table[g3 ^ key2] ^ g2
    g5 = f_table[g4 ^ key3] ^ g3
    g6 = f_table[g5 ^ key4] ^ g4
    if VERBOSE: print("g1:", hex(g1), "g2:", hex(g2), "g3:", hex(g3), "g4:", hex(g4), "g5:", hex(g5), "g6:", hex(g6))
    return concatenate_two_hexes(g5, g6)


def F(R0, R1, round):
    key_list = []
    if ENCRYPTION:
        start = 0; end = 12; step = 1
    else:
        start = 11; end = -1; step = -1
    for i in range(start, end, step):
        key_list.append(K(4*round+i%4))
    if DEBUG: print("key list:", key_list)
    if ENCRYPTION == False:
        key_list = list(reversed(key_list))
    T0 = G(R0, key_list[0], key_list[1], key_list[2], key_list[3])
    T1 = G(R1, key_list[4], key_list[5], key_list[6], key_list[7])
    F0 = (T0 + 2 * T1 + concatenate_two_hexes(key_list[8], key_list[9])) % 2**16
    F1 = (2 * T0 + T1 + concatenate_two_hexes(key_list[10], key_list[11])) % 2**16
    if VERBOSE: print("t0:", hex(T0), "t1:", hex(T1))
    if VERBOSE: print("f0:", hex(F0), "f1:", hex(F1))
    return (F0, F1)


def input_whitening(w0, w1, w2, w3):
    """
    Performs the initial whitening step in encrypt/decrypt
    - Parameters: A 64 bit block divided into 4 16-bit words w0, w1, w2, w3
    """
    K0,K1,K2,K3 = hex_to_hex_quarters(KEY)
    R0 = w0 ^ K0
    R1 = w1 ^ K1
    R2 = w2 ^ K2
    R3 = w3 ^ K3
    return (R0, R1, R2, R3)


def output_whitening(y0, y1, y2, y3):
    """
    Performs the final whitening step in encryp/decrypt
    - Parameters: A 64 bit block divided into 4 16-bit words y0, y1, y2, y3
    """
    K0,K1,K2,K3 = hex_to_hex_quarters(KEY)
    C0 = y0 ^ K0
    C1 = y1 ^ K1
    C2 = y2 ^ K2
    C3 = y3 ^ K3
    return (C0, C1, C2, C3)


def crypt(text): # incoming text is in form of 64bit hex value
    w0, w1, w2, w3 = hex_to_hex_quarters(text)
    if DEBUG: print("w0:", hex(w0))
    if DEBUG: print("w1:", hex(w1))
    if DEBUG: print("w2:", hex(w2))
    if DEBUG: print("w3:", hex(w3))
    R0, R1, R2, R3 = input_whitening(w0, w1, w2, w3)
    
    if ENCRYPTION:
        start = 0; end = 16; step = 1
    else:
        start = 15; end = -1; step = -1
    round = 0
    for i in range(start, end, step):
        if DEBUG: print("on the i'th step of crypt:", i)
        if VERBOSE: print("Beginning of Round: " + str(round))
        F0, F1 = F(R0, R1, i)
        newR0 = R2 ^ F0
        newR1 = R3 ^ F1
        R2 = R0
        R3 = R1
        R0 = newR0
        R1 = newR1
        if VERBOSE: print("End of Round: " + str(round) + "\n")
        round += 1
    y0 = R2
    y1 = R3
    y2 = R0
    y3 = R1
    C0, C1, C2, C3 = output_whitening(y0, y1, y2, y3)
    cryption = (C0 << 48) | (C1 << 32) | (C2 << 16) | (C3)
    return cryption


def main():
    global ENCRYPTION
    print("""
==============================
========= Encrypting =========
==============================
    """)

    hex_blocks = get_plaintext_input_as_hex_blocks()
    read_key()
    if DEBUG: print("key:", hex(KEY))
    ciphertext_hex = 0
    for block in hex_blocks:
        ciphertext_hex = concatenate_two_hexes(ciphertext_hex, crypt(block), 64)
    if DEBUG: print("Ciphertext:", hex(ciphertext_hex))
    file_output(ciphertext_hex)

    print("""
==============================
========= Decrypting =========
==============================
    """)

    ENCRYPTION = False
    ciphertext_chunks = get_ciphertext_input_chunks()
    if DEBUG: print(ciphertext_chunks)
    plaintext = ""
    for chunk in ciphertext_chunks:
        if DEBUG: print("chunk:", hex(chunk))
        if DEBUG: print("chunk int:", chunk)
        decrypted_chunk = crypt(chunk)
        if DEBUG: print(hex(decrypted_chunk))
        plaintext += hex_to_ascii(decrypted_chunk)
        if DEBUG: print("plaintext:", plaintext)
        
    file_output(plaintext)


if __name__ == '__main__':
    print("=== Welcome to the WSU-Crypt program ===")
    main()