# SM4基础实现
class SM4:
    # S盒定义
    SBOX = [
        0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
        0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
        0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
        0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
        0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
        0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
        0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
        0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
        0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
        0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
        0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
        0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
        0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
        0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
        0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
    ]

    # 系统参数FK
    FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]

    # 固定参数CK
    CK = [
        0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
        0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
        0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
        0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
        0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
        0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
        0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
        0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
    ]

    def __init__(self, key):
        if len(key) != 16:
            raise ValueError("SM4 key must be 16 bytes long")
        self.rk = self._expand_key(key)

    @staticmethod
    def _rotl32(x, n):
        return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

    def _tau(self, a):
        t = 0
        for i in range(4):
            t |= (self.SBOX[(a >> (i * 8 + 4)) & 0xF] << (i * 8 + 4))
            t |= (self.SBOX[(a >> (i * 8)) & 0xF] << (i * 8))
        return t

    def _l(self, b):
        return b ^ self._rotl32(b, 2) ^ self._rotl32(b, 10) ^ self._rotl32(b, 18) ^ self._rotl32(b, 24)

    def _l_prime(self, b):
        return b ^ self._rotl32(b, 13) ^ self._rotl32(b, 23)

    def _t(self, x):
        return self._l(self._tau(x))

    def _t_prime(self, x):
        return self._l_prime(self._tau(x))

    def _expand_key(self, mk):
        rk = [0] * 32
        k = [0] * 36

        for i in range(4):
            k[i] = int.from_bytes(mk[i * 4:(i + 1) * 4], 'big') ^ self.FK[i]

        for i in range(32):
            k[i + 4] = k[i] ^ self._t_prime(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ self.CK[i])
            rk[i] = k[i + 4]

        return rk

    def encrypt_block(self, plaintext):
        if len(plaintext) != 16:
            raise ValueError("SM4 block size must be 16 bytes")

        x = [0] * 36
        for i in range(4):
            x[i] = int.from_bytes(plaintext[i * 4:(i + 1) * 4], 'big')

        for i in range(32):
            x[i + 4] = x[i] ^ self._t(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ self.rk[i])

        ciphertext = b''
        for i in range(35, 31, -1):
            ciphertext += x[i].to_bytes(4, 'big')

        return ciphertext

    def decrypt_block(self, ciphertext):
        if len(ciphertext) != 16:
            raise ValueError("SM4 block size must be 16 bytes")

        x = [0] * 36
        for i in range(4):
            x[i] = int.from_bytes(ciphertext[i * 4:(i + 1) * 4], 'big')

        for i in range(32):
            x[i + 4] = x[i] ^ self._t(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ self.rk[31 - i])

        plaintext = b''
        for i in range(35, 31, -1):
            plaintext += x[i].to_bytes(4, 'big')

        return plaintext


# T-table优化版本
class SM4_TTable(SM4):
    def __init__(self, key):
        super().__init__(key)
        self.T_table = self._init_T_table()

    def _init_T_table(self):
        table = [[0] * 256 for _ in range(4)]
        for i in range(256):
            b = (self.SBOX[i >> 4] << 4) | self.SBOX[i & 0xF]
            table[0][i] = b
            table[1][i] = self._rotl32(b, 2)
            table[2][i] = self._rotl32(b, 10)
            table[3][i] = self._rotl32(b, 18)
        return table

    def _t(self, x):
        t0 = self.T_table[0][(x >> 24) & 0xFF]
        t1 = self.T_table[1][(x >> 16) & 0xFF]
        t2 = self.T_table[2][(x >> 8) & 0xFF]
        t3 = self.T_table[3][x & 0xFF]
        return t0 ^ t1 ^ t2 ^ t3 ^ self._rotl32(t0 ^ t1 ^ t2 ^ t3, 24)


# GCM模式实现
class SM4_GCM:
    def __init__(self, key, nonce):
        if len(key) != 16:
            raise ValueError("SM4 key must be 16 bytes long")
        if len(nonce) not in (12, 13, 14, 15, 16):
            raise ValueError("GCM nonce should be 12-16 bytes long")

        self.cipher = SM4_TTable(key)
        self.nonce = nonce
        self.H = self._init_H()
        self.block_size = 16

    def _init_H(self):
        zero_block = bytes(16)
        return int.from_bytes(self.cipher.encrypt_block(zero_block), 'big')

    def _ghash(self, data):
        pad_len = (16 - (len(data) % 16)) % 16
        data += bytes(pad_len)

        result = 0
        for i in range(0, len(data), 16):
            block = int.from_bytes(data[i:i + 16], 'big')
            result = self._multiply_ghash(result ^ block)

        return result

    def _multiply_ghash(self, x):
        z = 0
        v = self.H

        for i in range(128):
            if (x >> (127 - i)) & 1:
                z ^= v
            if v & 1:
                v = (v >> 1) ^ 0xE1000000000000000000000000000000
            else:
                v >>= 1

        return z

    def _inc32(self, counter):
        counter = bytearray(counter)
        for i in range(15, 11, -1):
            counter[i] += 1
            if counter[i] != 0:
                break
        return bytes(counter)

    def encrypt(self, plaintext, aad=b''):
        if len(self.nonce) == 12:
            counter = self.nonce + b'\x00\x00\x00\x01'
        else:
            counter = self._ghash([self.nonce])[:16]
            counter = counter[:-4] + b'\x00\x00\x00\x01'

        keystream = b''
        blocks = (len(plaintext) + 15) // 16
        for i in range(blocks):
            keystream += self.cipher.encrypt_block(counter)
            counter = self._inc32(counter)

        ciphertext = bytes(a ^ b for a, b in zip(plaintext, keystream[:len(plaintext)]))

        len_aad = len(aad)
        len_ct = len(ciphertext)
        auth_data = (
                aad +
                bytes((16 - (len_aad % 16)) % 16) +
                ciphertext +
                bytes((16 - (len_ct % 16)) % 16) +
                (len_aad * 8).to_bytes(8, 'big') +
                (len_ct * 8).to_bytes(8, 'big')
        )

        s = self._ghash(auth_data)
        t = self.cipher.encrypt_block(counter)
        tag = bytes(a ^ b for a, b in zip(t, s.to_bytes(16, 'big')))

        return ciphertext, tag

    def decrypt(self, ciphertext, tag, aad=b''):
        if len(self.nonce) == 12:
            counter = self.nonce + b'\x00\x00\x00\x01'
        else:
            counter = self._ghash([self.nonce])[:16]
            counter = counter[:-4] + b'\x00\x00\x00\x01'

        len_aad = len(aad)
        len_ct = len(ciphertext)
        auth_data = (
                aad +
                bytes((16 - (len_aad % 16)) % 16) +
                ciphertext +
                bytes((16 - (len_ct % 16)) % 16) +
                (len_aad * 8).to_bytes(8, 'big') +
                (len_ct * 8).to_bytes(8, 'big')
        )

        s = self._ghash(auth_data)
        t = self.cipher.encrypt_block(counter)
        computed_tag = bytes(a ^ b for a, b in zip(t, s.to_bytes(16, 'big')))

        if computed_tag != tag:
            raise ValueError("Authentication failed - invalid tag")

        keystream = b''
        blocks = (len(ciphertext) + 15) // 16
        for i in range(blocks):
            keystream += self.cipher.encrypt_block(counter)
            counter = self._inc32(counter)

        plaintext = bytes(a ^ b for a, b in zip(ciphertext, keystream[:len(ciphertext)]))

        return plaintext


# 测试函数
def test_sm4():
    print("Testing SM4 encryption...")
    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    plaintext = bytes.fromhex("0123456789abcdeffedcba9876543210")

    sm4 = SM4(key)
    ciphertext = sm4.encrypt_block(plaintext)
    decrypted = sm4.decrypt_block(ciphertext)
    print(f"Original:  {plaintext.hex()}")
    print(f"Encrypted: {ciphertext.hex()}")
    print(f"Decrypted: {decrypted.hex()}")
    assert decrypted == plaintext, "SM4 basic test failed"

    sm4_tt = SM4_TTable(key)
    ciphertext_tt = sm4_tt.encrypt_block(plaintext)
    decrypted_tt = sm4_tt.decrypt_block(ciphertext_tt)
    assert ciphertext_tt == ciphertext, "T-table implementation mismatch"
    assert decrypted_tt == plaintext, "SM4 T-table test failed"

    print("All SM4 tests passed!\n")


def test_sm4_gcm():
    print("Testing SM4-GCM mode...")
    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    nonce = bytes.fromhex("000000000000000000000000")
    aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    plaintext = bytes.fromhex(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")

    gcm = SM4_GCM(key, nonce)
    ciphertext, tag = gcm.encrypt(plaintext, aad)
    print(f"Plaintext length: {len(plaintext)} bytes")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Tag: {tag.hex()}")

    decrypted = gcm.decrypt(ciphertext, tag, aad)
    assert decrypted == plaintext, "SM4-GCM test failed"

    print("All SM4-GCM tests passed!")


if __name__ == "__main__":
    test_sm4()
    test_sm4_gcm()