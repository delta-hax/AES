#
# Constants
#

RJ_MATRIX = [[2, 3, 1, 1], 
             [1, 2, 3, 1], 
             [1, 1, 2, 3], 
             [3, 1, 1, 2]]

ROUND_CONST = [2**0, 2**1, 2**2, 2**3, 2**4, 2**5, 2**6, 2**7, 27, 54]

SBOX = [0x63 ,0x7c ,0x77 ,0x7b ,0xf2 ,0x6b ,0x6f ,0xc5 ,0x30 ,0x01 ,0x67 ,0x2b ,0xfe ,0xd7 ,0xab ,0x76,
        0xca ,0x82 ,0xc9 ,0x7d ,0xfa ,0x59 ,0x47 ,0xf0 ,0xad ,0xd4 ,0xa2 ,0xaf ,0x9c ,0xa4 ,0x72 ,0xc0,
        0xb7 ,0xfd ,0x93 ,0x26 ,0x36 ,0x3f ,0xf7 ,0xcc ,0x34 ,0xa5 ,0xe5 ,0xf1 ,0x71 ,0xd8 ,0x31 ,0x15,
        0x04 ,0xc7 ,0x23 ,0xc3 ,0x18 ,0x96 ,0x05 ,0x9a ,0x07 ,0x12 ,0x80 ,0xe2 ,0xeb ,0x27 ,0xb2 ,0x75,
        0x09 ,0x83 ,0x2c ,0x1a ,0x1b ,0x6e ,0x5a ,0xa0 ,0x52 ,0x3b ,0xd6 ,0xb3 ,0x29 ,0xe3 ,0x2f ,0x84,
        0x53 ,0xd1 ,0x00 ,0xed ,0x20 ,0xfc ,0xb1 ,0x5b ,0x6a ,0xcb ,0xbe ,0x39 ,0x4a ,0x4c ,0x58 ,0xcf,
        0xd0 ,0xef ,0xaa ,0xfb ,0x43 ,0x4d ,0x33 ,0x85 ,0x45 ,0xf9 ,0x02 ,0x7f ,0x50 ,0x3c ,0x9f ,0xa8,
        0x51 ,0xa3 ,0x40 ,0x8f ,0x92 ,0x9d ,0x38 ,0xf5 ,0xbc ,0xb6 ,0xda ,0x21 ,0x10 ,0xff ,0xf3 ,0xd2,
        0xcd ,0x0c ,0x13 ,0xec ,0x5f ,0x97 ,0x44 ,0x17 ,0xc4 ,0xa7 ,0x7e ,0x3d ,0x64 ,0x5d ,0x19 ,0x73,
        0x60 ,0x81 ,0x4f ,0xdc ,0x22 ,0x2a ,0x90 ,0x88 ,0x46 ,0xee ,0xb8 ,0x14 ,0xde ,0x5e ,0x0b ,0xdb,
        0xe0 ,0x32 ,0x3a ,0x0a ,0x49 ,0x06 ,0x24 ,0x5c ,0xc2 ,0xd3 ,0xac ,0x62 ,0x91 ,0x95 ,0xe4 ,0x79,
        0xe7 ,0xc8 ,0x37 ,0x6d ,0x8d ,0xd5 ,0x4e ,0xa9 ,0x6c ,0x56 ,0xf4 ,0xea ,0x65 ,0x7a ,0xae ,0x08,
        0xba ,0x78 ,0x25 ,0x2e ,0x1c ,0xa6 ,0xb4 ,0xc6 ,0xe8 ,0xdd ,0x74 ,0x1f ,0x4b ,0xbd ,0x8b ,0x8a,
        0x70 ,0x3e ,0xb5 ,0x66 ,0x48 ,0x03 ,0xf6 ,0x0e ,0x61 ,0x35 ,0x57 ,0xb9 ,0x86 ,0xc1 ,0x1d ,0x9e,
        0xe1 ,0xf8 ,0x98 ,0x11 ,0x69 ,0xd9 ,0x8e ,0x94 ,0x9b ,0x1e ,0x87 ,0xe9 ,0xce ,0x55 ,0x28 ,0xdf,
        0x8c ,0xa1 ,0x89 ,0x0d ,0xbf ,0xe6 ,0x42 ,0x68 ,0x41 ,0x99 ,0x2d ,0x0f ,0xb0 ,0x54 ,0xbb ,0x16]

#
# Helper functions
#

# logic based on https://www.angelfire.com/biz7/atleast/mix_columns.pdf
def binary_multiply(hex1, rjval):
    if rjval == 1:
        return int(hex1, base=16)
    else:
        bin1 = '{0:08b}'.format(int(hex1, 16))
        start = bin1[0]
        result = int(bin1[1:] + '0', 2)
        if start == '1':
            result = result ^ int('00011011', 2)
        if rjval == 3:
            result = result ^ int(bin1, 2)
        return result

def multiply_and_xor(list1, list2):
    multiply_result = []
    for i in range(4):
        result = binary_multiply(list2[i], list1[i])
        multiply_result.append(result)
    xor_result = hex(multiply_result[0] ^ multiply_result[1] ^ multiply_result[2] ^ multiply_result[3])
    return xor_result

def string_to_hex(text):
    hex_list = []
    for char in text:
        hex_list.append(hex(ord(char)))
    return hex_list

#
# AES Operations
#

def generate_round_keys(hex_list, round_constant):
    key = []
    for i in range(0, 16, 4):
        key.append(hex_list[i:i + 4])
    w3 = sbox_sub(key[3][1:] + [key[3][0]])
    w3[0] = hex(round_constant ^ int(w3[0],base=16))
    w4 = [hex(int(key[0][i],base=16) ^ int(w3[i],base=16)) for i in range(4)]
    w5 = [hex(int(w4[i],base=16) ^ int(key[1][i],base=16)) for i in range(4)]
    w6 = [hex(int(w5[i],base=16) ^ int(key[2][i],base=16)) for i in range(4)]
    w7 = [hex(int(w6[i],base=16) ^ int(key[3][i],base=16)) for i in range(4)]
    return w4 + w5 + w6 + w7

def xor_roundkey(value, round_key):
    result = []
    for i in range(len(value)):
        if isinstance(value, str): 
            result.append(hex(ord(value[i]) ^ int(round_key[i], base=16)))
        else:
            result.append(hex(int(value[i], base=16) ^ int(round_key[i], base=16)))
    return result

def shift_row(hex_list):
    rows = [hex_list[::4], hex_list[1::4], hex_list[2::4], hex_list[3::4]]
    for pos in range(1, 4):
        rows[pos] = rows[pos][pos:] + rows[pos][:pos]
    for pos in range(0, 4):
        for row_pos in range(0, 4):
            hex_list[(pos * 4) + row_pos] = rows[row_pos][pos]
    return hex_list

def mix_columns(hex_list):
    columns = [hex_list[0:4], hex_list[4:8], hex_list[8:12], hex_list[12:16]]
    result = []
    for r in RJ_MATRIX:
        for c in columns:
            value = multiply_and_xor(r, c)
            result.append(value)
    columns = [result[::4], result[1::4], result[2::4], result[3::4]]
    result = columns[0] + columns[1] + columns[2] + columns[3]
    return result

def sbox_sub(hex_list):
    lowercase_a = ord('a')
    result = []
    for i in range(len(hex_list)):
        # ignore the 0x from hex numbers
        if len(hex_list[i]) == 4:
            row = hex_list[i][2]
            column = hex_list[i][3]
        else:
            row = '0'
            column = hex_list[i][2]
        
        if ord(row) >= lowercase_a:
            row = ord(row) - lowercase_a + 10
        else:
            row = int(row)
        if ord(column) >= lowercase_a:
            column = ord(column) - lowercase_a + 10
        else:
            column = int(column)
        new_hex = SBOX[column + (row * 16)]
        result.append(hex(new_hex))
    return result

def encrypt(plaintext, key):
    # generate round keys
    round_keys = []
    for i in range(10):
        if i == 0:
            round_keys.append(string_to_hex(key))
        round_keys.append(generate_round_keys(round_keys[i], ROUND_CONST[i]))

    # run algorithm
    ciphertext = xor_roundkey(plaintext, round_keys[0])
    for i in range(1,11):
        ciphertext = sbox_sub(ciphertext)
        ciphertext = shift_row(ciphertext)
        if i != 10:
            ciphertext = mix_columns(ciphertext)
        ciphertext = xor_roundkey(ciphertext, round_keys[i])
    ciphertext = " ".join(ciphertext)
    return ciphertext


#
# Program Execution
#

def main():
    sixteen_chars = 16
    key = input("Enter 16 character (128-bit) key:")
    key_valid = False
    while not key_valid:
        if len(key) == 16:
            key_valid = True
            continue
        print("Invalid Key. Please enter a 16 character (128-bit) key")
    plaintext = input("Enter plaintext to encrypt:")
    ciphertext = ""
    while plaintext:
        if len(plaintext) < sixteen_chars:
            padding = "0" * (sixteen_chars - len(plaintext))
            ciphertext += encrypt(plaintext + padding, key)
            plaintext = ""
            continue
        ciphertext += encrypt(plaintext[:sixteen_chars], key)
        plaintext = plaintext[sixteen_chars:]
    print(ciphertext)

main()