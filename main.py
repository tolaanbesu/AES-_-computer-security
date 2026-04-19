# Group members
# Lisan Gebretensay   UGR/1712/15
# Tola Anbesu         UGR/7995/15
# Nathnael Hailemariam  UGR/9299/16
# Yohannes Gizaw       UGR/6435/15

# AES-128 code

# --- FULL S-BOX ---
S_BOX = [
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]

INV_S_BOX = [0]*256
for i in range(256):
    INV_S_BOX[S_BOX[i]] = i

# --- BASIC ---
def sub_bytes(s): return [S_BOX[b] for b in s]
def inv_sub_bytes(s): return [INV_S_BOX[b] for b in s]

def shift_rows(s):
    return [s[0],s[5],s[10],s[15], s[4],s[9],s[14],s[3],
            s[8],s[13],s[2],s[7], s[12],s[1],s[6],s[11]]

def inv_shift_rows(s):
    return [s[0],s[13],s[10],s[7], s[4],s[1],s[14],s[11],
            s[8],s[5],s[2],s[15], s[12],s[9],s[6],s[3]]

def xtime(a): return ((a<<1)^0x1b)&0xff if a&0x80 else a<<1

def mix_columns(s):
    for i in range(4):
        col = s[i*4:(i+1)*4]
        t = col[0]^col[1]^col[2]^col[3]
        u = col[0]
        col[0] ^= t ^ xtime(col[0]^col[1])
        col[1] ^= t ^ xtime(col[1]^col[2])
        col[2] ^= t ^ xtime(col[2]^col[3])
        col[3] ^= t ^ xtime(col[3]^u)
        s[i*4:(i+1)*4] = col
    return s

def mul(a, b):
    # GF(2^8 multiplication
    p = 0
    for i in range(8):
        if b & 1:
            p ^= a
        hi_bit = a & 0x80
        a = (a << 1) & 0xff
        if hi_bit:
            a ^= 0x1b
        b >>= 1
    return p

def inv_mix_columns(s):
    for i in range(4):
        a0, a1, a2, a3 = s[i*4:(i+1)*4]

        s[i*4+0] = mul(a0,14) ^ mul(a1,11) ^ mul(a2,13) ^ mul(a3,9)
        s[i*4+1] = mul(a0,9)  ^ mul(a1,14) ^ mul(a2,11) ^ mul(a3,13)
        s[i*4+2] = mul(a0,13) ^ mul(a1,9)  ^ mul(a2,14) ^ mul(a3,11)
        s[i*4+3] = mul(a0,11) ^ mul(a1,13) ^ mul(a2,9)  ^ mul(a3,14)

    return s

def add_round_key(s,k): return [a^b for a,b in zip(s,k)]

# --- KEY EXPANSION (FIX ADDED) ---
RCON = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]

def rot_word(w): return w[1:] + w[:1]
def sub_word(w): return [S_BOX[b] for b in w]

def key_expansion(key):
    w = [key[i:i+4] for i in range(0,16,4)]

    for i in range(4,44):
        temp = w[i-1][:]
        if i % 4 == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= RCON[i//4]
        w.append([a^b for a,b in zip(w[i-4], temp)])

    round_keys = []
    for i in range(0,44,4):
        rk = []
        for j in range(4):
            rk += w[i+j]
        round_keys.append(rk)

    return round_keys

def pad(t): return list(t.encode().ljust(16,b'\0')[:16])
def key_to_bytes(k): return list(k.encode().ljust(16,b'\0')[:16])

# --- ENCRYPT (FIXED AES STRUCTURE) ---
def encrypt(b,k):
    rk = key_expansion(k)

    s = add_round_key(b, rk[0])

    for i in range(1,10):
        s = sub_bytes(s)
        s = shift_rows(s)
        s = mix_columns(s)
        s = add_round_key(s, rk[i])

    s = sub_bytes(s)
    s = shift_rows(s)
    s = add_round_key(s, rk[10])

    return s

# --- DECRYPT (FIXED AES STRUCTURE) ---
def decrypt(b,k):
    rk = key_expansion(k)

    s = add_round_key(b, rk[10])

    for i in range(9,0,-1):
        s = inv_shift_rows(s)
        s = inv_sub_bytes(s)
        s = add_round_key(s, rk[i])
        s = inv_mix_columns(s)

    s = inv_shift_rows(s)
    s = inv_sub_bytes(s)
    s = add_round_key(s, rk[0])

    return s

# --- MAIN LOOP ---
def main():
    while True:
        print("\n===== AES Program =====")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Exit")

        try:
            choice = input("Choose (1/2/3): ").strip()

            if choice == "3":
                print("Exiting program...")
                break

            if choice not in ["1", "2"]:
                print("Invalid choice! Please enter 1, 2, or 3.")
                continue

            key_input = input("Enter key: ")
            if not key_input:
                print("Key cannot be empty!")
                continue

            key = key_to_bytes(key_input)

            if choice == "1":
                text = input("Enter plaintext: ")
                if not text:
                    print("Plaintext cannot be empty!")
                    continue

                result = encrypt(pad(text), key)
                print("Cipher (hex):", ''.join(f"{b:02x}" for b in result))

            elif choice == "2":
                hex_input = input("Enter cipher (32 hex chars): ").strip()

                if len(hex_input) != 32:
                    print("Invalid cipher length!")
                    continue

                block = [int(hex_input[i:i+2],16) for i in range(0,32,2)]
                result = decrypt(block, key)
                print("Decrypted:", bytes(result).decode(errors='ignore').strip('\0'))

        except Exception as e:
            print("Error:", str(e))

if __name__ == "__main__":
    main()

# # AES-128 (Educational) - Fixed Version
#
# # --- FULL S-BOX ---
# S_BOX = [
# 0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
# 0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
# 0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
# 0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
# 0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
# 0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
# 0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
# 0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
# 0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
# 0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
# 0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
# 0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
# 0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
# 0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
# 0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
# 0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]
#
# INV_S_BOX = [0]*256
# for i in range(256):
#     INV_S_BOX[S_BOX[i]] = i
#
# # --- BASIC ---
# def sub_bytes(s): return [S_BOX[b] for b in s]
# def inv_sub_bytes(s): return [INV_S_BOX[b] for b in s]
#
# def shift_rows(s):
#     return [s[0],s[5],s[10],s[15], s[4],s[9],s[14],s[3],
#             s[8],s[13],s[2],s[7], s[12],s[1],s[6],s[11]]
#
# def inv_shift_rows(s):
#     return [s[0],s[13],s[10],s[7], s[4],s[1],s[14],s[11],
#             s[8],s[5],s[2],s[15], s[12],s[9],s[6],s[3]]
#
# def xtime(a): return ((a<<1)^0x1b)&0xff if a&0x80 else a<<1
#
# def mix_columns(s):
#     for i in range(4):
#         col = s[i*4:(i+1)*4]
#         t = col[0]^col[1]^col[2]^col[3]
#         u = col[0]
#         col[0] ^= t ^ xtime(col[0]^col[1])
#         col[1] ^= t ^ xtime(col[1]^col[2])
#         col[2] ^= t ^ xtime(col[2]^col[3])
#         col[3] ^= t ^ xtime(col[3]^u)
#         s[i*4:(i+1)*4] = col
#     return s
#
# #  inverse mix
# def inv_mix_columns(s):
#     for i in range(4):
#         col = s[i*4:(i+1)*4]
#         u = xtime(xtime(col[0]^col[2]))
#         v = xtime(xtime(col[1]^col[3]))
#         col[0] ^= u
#         col[1] ^= v
#         col[2] ^= u
#         col[3] ^= v
#         s[i*4:(i+1)*4] = col
#     return mix_columns(s)
#
# def add_round_key(s,k): return [a^b for a,b in zip(s,k)]
#
# def pad(t): return list(t.encode().ljust(16,b'\0')[:16])
# def key_to_bytes(k): return list(k.encode().ljust(16,b'\0')[:16])
#
# # --- ENCRYPT ---
# def encrypt(b,k):
#     s = add_round_key(b,k)
#     for _ in range(9):
#         s = add_round_key(mix_columns(shift_rows(sub_bytes(s))),k)
#     return add_round_key(shift_rows(sub_bytes(s)),k)
#
# # --- DECRYPT ---
# def decrypt(b,k):
#     s = add_round_key(b,k)
#     for _ in range(9):
#         s = inv_mix_columns(add_round_key(inv_sub_bytes(inv_shift_rows(s)),k))
#     return add_round_key(inv_sub_bytes(inv_shift_rows(s)),k)
#
# # --- MAIN LOOP ---
# def main():
#     while True:
#         print("\n===== AES Program =====")
#         print("1. Encrypt")
#         print("2. Decrypt")
#         print("3. Exit")
#
#         try:
#             choice = input("Choose (1/2/3): ").strip()
#
#             if choice == "3":
#                 print("Exiting program...")
#                 break
#
#             if choice not in ["1", "2"]:
#                 print("Invalid choice! Please enter 1, 2, or 3.")
#                 continue
#
#             # --- KEY INPUT ---
#             key_input = input("Enter key (max 16 chars): ")
#             if not key_input:
#                 print("Key cannot be empty!")
#                 continue
#
#             key = key_to_bytes(key_input)
#
#             # --- ENCRYPT ---
#             if choice == "1":
#                 text = input("Enter plaintext: ")
#
#                 if not text:
#                     print("Plaintext cannot be empty!")
#                     continue
#
#                 try:
#                     result = encrypt(pad(text), key)
#                     print("Cipher (hex):", ''.join(f"{b:02x}" for b in result))
#                 except Exception as e:
#                     print("Encryption error:", str(e))
#
#             # --- DECRYPT ---
#             elif choice == "2":
#                 hex_input = input("Enter cipher (32 hex chars): ").strip()
#
#                 if len(hex_input) != 32:
#                     print("Invalid cipher length! Must be exactly 32 hex characters.")
#                     continue
#
#                 if not all(c in "0123456789abcdefABCDEF" for c in hex_input):
#                     print("Invalid hex input! Only hexadecimal characters allowed.")
#                     continue
#
#                 try:
#                     block = [int(hex_input[i:i+2], 16) for i in range(0, 32, 2)]
#                     result = decrypt(block, key)
#                     print("Decrypted:", bytes(result).decode(errors='ignore').strip('\0'))
#                 except ValueError:
#                     print("Conversion error! Invalid hex format.")
#                 except Exception as e:
#                     print("Decryption error:", str(e))
#
#         except KeyboardInterrupt:
#             print("\nProgram interrupted by user.")
#             break
#         except Exception as e:
#             print("Unexpected error:", str(e))
#
#
# if __name__ == "__main__":
#     main()