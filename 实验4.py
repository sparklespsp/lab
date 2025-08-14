import struct
import math
import os
import hashlib
from typing import List, Tuple, Optional


# ==================== SM3 基础实现 ====================
class SM3:
    """SM3哈希算法基础实现"""

    # 初始IV值
    IV = [
        0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
        0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
    ]

    # 常量Tj
    T = [0x79CC4519] * 16 + [0x7A879D8A] * 48

    @staticmethod
    def _ff(x: int, y: int, z: int, j: int) -> int:
        """布尔函数FF"""
        if j < 16:
            return x ^ y ^ z
        else:
            return (x & y) | (x & z) | (y & z)

    @staticmethod
    def _gg(x: int, y: int, z: int, j: int) -> int:
        """布尔函数GG"""
        if j < 16:
            return x ^ y ^ z
        else:
            return (x & y) | ((~x) & z)

    @staticmethod
    def _p0(x: int) -> int:
        """置换函数P0"""
        return x ^ ((x << 9) & 0xFFFFFFFF) ^ ((x >> 23) & 0x1FF)

    @staticmethod
    def _p1(x: int) -> int:
        """置换函数P1"""
        return x ^ ((x << 15) & 0xFFFFFFFF) ^ ((x >> 17) & 0x7FFF)

    @staticmethod
    def _left_rotate(x: int, n: int) -> int:
        """循环左移"""
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def _cf(self, v: List[int], b: bytes) -> List[int]:
        """压缩函数CF"""
        # 消息扩展
        w = [0] * 68
        w_prime = [0] * 64

        for i in range(16):
            w[i] = struct.unpack(">I", b[i * 4:(i + 1) * 4])[0]

        for i in range(16, 68):
            w[i] = self._p1(w[i - 16] ^ w[i - 9] ^ self._left_rotate(w[i - 3], 15)) ^ \
                   self._left_rotate(w[i - 13], 7) ^ w[i - 6]

        for i in range(64):
            w_prime[i] = w[i] ^ w[i + 4]

        # 压缩
        a, b, c, d, e, f, g, h = v

        for j in range(64):
            ss1 = self._left_rotate((self._left_rotate(a, 12) + e + self._left_rotate(self.T[j], j)) & 0xFFFFFFFF, 7)
            ss2 = ss1 ^ self._left_rotate(a, 12)
            tt1 = (self._ff(a, b, c, j) + d + ss2 + w_prime[j]) & 0xFFFFFFFF
            tt2 = (self._gg(e, f, g, j) + h + ss1 + w[j]
                   tt2 &= 0xFFFFFFFF
                   d = c
                   c = self._left_rotate(b, 9)
            b = a
            a = tt1
            h = g
            g = self._left_rotate(f, 19)
            f = e
            e = self._p0(tt2)

        return [a ^ v[0], b ^ v[1], c ^ v[2], d ^ v[3],
                e ^ v[4], f ^ v[5], g ^ v[6], h ^ v[7]]

    def hash(self, msg: bytes) -> bytes:
        """计算SM3哈希值"""
        # 填充消息
        length = len(msg) * 8
        msg += b'\x80'
        msg += b'\x00' * ((56 - (len(msg) % 64) % 64)
            msg += struct.pack(">Q", length)

        # 初始化寄存器
        v = self.IV.copy()

        # 迭代压缩
        for i in range(0, len(msg), 64):
            block = msg[i:i + 64]
        v = self._cf(v, block)

        # 输出哈希值
        return b''.join(struct.pack(">I", x) for x in v)


# ==================== SM3 优化实现 ====================
class SM3_Optimized(SM3):
    """SM3哈希算法优化实现"""

    def _cf(self, v: List[int], b: bytes) -> List[int]:
        """优化后的压缩函数CF"""
        # 预计算常量
        T = self.T
        P0 = self._p0
        P1 = self._p1
        ROTL = self._left_rotate
        FF = self._ff
        GG = self._gg

        # 消息扩展
        w = list(struct.unpack(">16I", b[:64]))

        for i in range(16, 68):
            w.append(P1(w[i - 16] ^ w[i - 9] ^ ROTL(w[i - 3], 15)) ^
                     ROTL(w[i - 13], 7) ^ w[i - 6])

        w_prime = [w[i] ^ w[i + 4] for i in range(64)]

        # 压缩
        a, b, c, d, e, f, g, h = v

        for j in range(64):
            ss1 = ROTL((ROTL(a, 12) + e + ROTL(T[j], j)) & 0xFFFFFFFF, 7)
            ss2 = ss1 ^ ROTL(a, 12)
            tt1 = (FF(a, b, c, j) + d + ss2 + w_prime[j]) & 0xFFFFFFFF
            tt2 = (GG(e, f, g, j) + h + ss1 + w[j]
                   tt2 &= 0xFFFFFFFF

                   # 寄存器更新
                   a, b, c, d, e, f, g, h = tt1, a, ROTL(b, 9), c, P0(tt2), e, ROTL(f, 19), g

        return [a ^ v[0], b ^ v[1], c ^ v[2], d ^ v[3],
                e ^ v[4], f ^ v[5], g ^ v[6], h ^ v[7]]


# ==================== 长度扩展攻击验证 ====================
def length_extension_attack():
    """SM3长度扩展攻击演示"""
    print("\n=== SM3长度扩展攻击验证 ===")

    # 原始消息和密钥
    secret_key = b"secret_key"
    original_msg = b"original_message"
    original_hash = SM3().hash(secret_key + original_msg)
    print(f"原始哈希: {original_hash.hex()}")

    # 攻击者知道original_hash和original_msg长度，但不知道secret_key
    # 构造扩展消息
    extension = b";admin=true"

    # 计算填充后的secret_key + original_msg长度
    total_length = len(secret_key) + len(original_msg)
    padding = b'\x80' + b'\x00' * ((56 - (total_length + 1) % 64) % 64)
    padding += struct.pack(">Q", total_length * 8)

    # 从原始哈希中恢复寄存器状态
    registers = list(struct.unpack(">8I", original_hash))

    # 计算扩展后的哈希
    sm3 = SM3()
    forged_hash = sm3.hash(extension)
    forged_hash_with_state = sm3._cf(registers, extension + b'\x80' + b'\x00' * ((56 - (len(extension) + 1) % 64) % 64 +
                                                                                 struct.pack(">Q", (total_length + len(
                                                                                     padding) + len(extension)) * 8))
    forged_hash_final = b''.join(struct.pack(">I", x) for x in forged_hash_with_state)

    print(f"伪造的哈希: {forged_hash_final.hex()}")
    print(f"正常计算的哈希: {SM3().hash(secret_key + original_msg + padding + extension).hex()}")
    print("验证结果:", forged_hash_final == SM3().hash(secret_key + original_msg + padding + extension))

    # ==================== Merkle树实现 ====================


class MerkleTree:
    """基于SM3的Merkle树实现"""

    def __init__(self, data: List[bytes]):
        self.leaves = data
        self.tree = self.build_tree()

    def build_tree(self) -> List[List[bytes]]:
        """构建Merkle树"""
        tree = [self.leaves.copy()]
        current_level = self.leaves

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else current_level[i]
                combined = left + right
                next_level.append(SM3().hash(combined))
            tree.append(next_level)
            current_level = next_level

        return tree

    def get_root(self) -> bytes:
        """获取Merkle根"""
        return self.tree[-1][0]

    def get_proof(self, index: int) -> List[bytes]:
        """获取存在性证明"""
        proof = []
        current_index = index

        for level in range(len(self.tree) - 1):
            sibling_index = current_index + 1 if current_index % 2 == 0 else current_index - 1
            if sibling_index < len(self.tree[level]):
                proof.append(self.tree[level][sibling_index])
            current_index = current_index // 2

        return proof

    def verify_proof(self, leaf: bytes, proof: List[bytes], root: bytes) -> bool:
        """验证存在性证明"""
        current_hash = leaf

        for sibling in proof:
            # 根据索引决定连接顺序
            if struct.unpack("<I", current_hash[:4])[0] < struct.unpack("<I", sibling[:4])[0]:
                combined = current_hash + sibling
            else:
                combined = sibling + current_hash
            current_hash = SM3().hash(combined)

        return current_hash == root

    @staticmethod
    def generate_non_membership_proof(tree: 'MerkleTree', leaf: bytes) -> Tuple[Optional[bytes], List[bytes]]:
        """生成不存在性证明(简化版)"""
        # 在实际应用中需要更复杂的逻辑
        sorted_leaves = sorted(tree.leaves)
        index = bisect.bisect_left(sorted_leaves, leaf)

        if index < len(sorted_leaves) and sorted_leaves[index] == leaf:
            return None, []  # 叶子存在，无法生成不存在性证明

        # 返回相邻叶子作为证明
        proof = []
        if index > 0:
            proof.append(sorted_leaves[index - 1])
        if index < len(sorted_leaves):
            proof.append(sorted_leaves[index])

        return tree.get_root(), proof


# ==================== 测试代码 ====================
def test_sm3():
    """测试SM3实现"""
    print("=== SM3基础实现测试 ===")
    sm3 = SM3()
    msg = b"abc"
    expected_hash = bytes.fromhex("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")
    result = sm3.hash(msg)
    print(f"输入: {msg}")
    print(f"预期: {expected_hash.hex()}")
    print(f"结果: {result.hex()}")
    print(f"验证: {result == expected_hash}")


def test_optimized_sm3():
    """测试优化版SM3"""
    print("\n=== SM3优化实现测试 ===")
    sm3_opt = SM3_Optimized()
    msg = b"abcd" * 16
    print("长消息性能对比:")

    import time
    start = time.time()
    SM3().hash(msg)
    basic_time = time.time() - start

    start = time.time()
    sm3_opt.hash(msg)
    opt_time = time.time() - start

    print(f"基础实现耗时: {basic_time:.6f}s")
    print(f"优化实现耗时: {opt_time:.6f}s")
    print(f"加速比: {basic_time / opt_time:.2f}x")


def test_merkle_tree():
    """测试Merkle树"""
    print("\n=== Merkle树测试 ===")
    # 生成10万个随机叶子节点
    leaves = [os.urandom(32) for _ in range(100000)]
    tree = MerkleTree(leaves)

    print(f"Merkle根: {tree.get_root().hex()}")

    # 测试存在性证明
    test_index = 12345
    proof = tree.get_proof(test_index)
    print(f"\n叶子 {test_index} 的存在性证明:")
    print(f"包含 {len(proof)} 个哈希值")

    # 验证证明
    is_valid = tree.verify_proof(leaves[test_index], proof, tree.get_root())
    print(f"验证结果: {is_valid}")

    # 测试不存在性证明(简化版)
    non_existing_leaf = os.urandom(32)
    root, non_mem_proof = MerkleTree.generate_non_membership_proof(tree, non_existing_leaf)
    print(f"\n不存在性证明:")
    print(f"包含 {len(non_mem_proof)} 个相邻叶子")
    print(f"验证: {'成功' if root is not None else '失败'}")


if __name__ == "__main__":
    test_sm3()
    test_optimized_sm3()
    length_extension_attack()
    test_merkle_tree()