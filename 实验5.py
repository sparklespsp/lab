import random
import hashlib
import binascii
from typing import Tuple


# ==================== SM2 基础实现 ====================
class SM2:
    """SM2椭圆曲线密码算法实现"""

    # 椭圆曲线参数 (SM2推荐参数)
    P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
    A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
    B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
    N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
    Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
    Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
    G = (Gx, Gy)

    @staticmethod
    def _mod_inv(a: int, p: int) -> int:
        """模逆运算"""
        return pow(a, p - 2, p)

    @classmethod
    def _point_add(cls, P: Tuple[int, int], Q: Tuple[int, int]) -> Tuple[int, int]:
        """椭圆曲线点加法"""
        if P == (0, 0):
            return Q
        if Q == (0, 0):
            return P
        if P[0] == Q[0] and (P[1] + Q[1]) % cls.P == 0:
            return (0, 0)

        if P != Q:
            lam = (Q[1] - P[1]) * cls._mod_inv(Q[0] - P[0], cls.P) % cls.P
        else:
            lam = (3 * P[0] ** 2 + cls.A) * cls._mod_inv(2 * P[1], cls.P) % cls.P

        x = (lam ** 2 - P[0] - Q[0]) % cls.P
        y = (lam * (P[0] - x) - P[1]) % cls.P
        return (x, y)

    @classmethod
    def _point_mul(cls, k: int, P: Tuple[int, int]) -> Tuple[int, int]:
        """椭圆曲线点乘法"""
        R = (0, 0)
        while k > 0:
            if k % 2 == 1:
                R = cls._point_add(R, P)
            P = cls._point_add(P, P)
            k = k // 2
        return R

    @classmethod
    def _hash(cls, msg: bytes) -> int:
        """SM3哈希函数(简化版)"""
        h = hashlib.sha256(msg).digest()  # 实际应使用SM3，这里简化
        return int.from_bytes(h, 'big') % cls.N

    @classmethod
    def generate_key_pair(cls) -> Tuple[int, Tuple[int, int]]:
        """生成密钥对"""
        d = random.randint(1, cls.N - 1)
        P = cls._point_mul(d, cls.G)
        return d, P

    @classmethod
    def sign(cls, d: int, msg: bytes) -> Tuple[int, int]:
        """SM2签名"""
        e = cls._hash(msg)
        while True:
            k = random.randint(1, cls.N - 1)
            x1, _ = cls._point_mul(k, cls.G)
            r = (e + x1) % cls.N
            if r == 0 or r + k == cls.N:
                continue
            s = (cls._mod_inv(1 + d, cls.N) * (k - r * d)) % cls.N
            if s != 0:
                return r, s

    @classmethod
    def verify(cls, P: Tuple[int, int], msg: bytes, signature: Tuple[int, int]) -> bool:
        """SM2验证"""
        r, s = signature
        if not (1 <= r < cls.N and 1 <= s < cls.N):
            return False

        e = cls._hash(msg)
        t = (r + s) % cls.N
        if t == 0:
            return False

        x1, y1 = cls._point_mul(s, cls.G)
        x2, y2 = cls._point_mul(t, P)
        x1, y1 = cls._point_add((x1, y1), (x2, y2))
        R = (e + x1) % cls.N
        return R == r


# ==================== 签名算法误用验证 ====================
def test_signature_misuse():
    """测试签名算法误用情况"""
    print("\n=== 签名算法误用验证 ===")

    # 1. 相同k值导致的私钥泄露
    print("1. 相同k值攻击:")
    d, P = SM2.generate_key_pair()
    msg1 = b"message1"
    msg2 = b"message2"

    # 故意使用相同k值签名
    k = random.randint(1, SM2.N - 1)

    # 签名函数修改为可传入k值
    def sign_with_k(d, msg, k):
        e = SM2._hash(msg)
        x1, _ = SM2._point_mul(k, SM2.G)
        r = (e + x1) % SM2.N
        s = (SM2._mod_inv(1 + d, SM2.N) * (k - r * d)) % SM2.N
        return r, s

    sig1 = sign_with_k(d, msg1, k)
    sig2 = sign_with_k(d, msg2, k)

    # 从两个签名中恢复私钥
    e1 = SM2._hash(msg1)
    e2 = SM2._hash(msg2)
    r1, s1 = sig1
    r2, s2 = sig2

    # 计算私钥d
    d_recovered = ((s2 - s1) * SM2._mod_inv(s1 * r1 - s2 * r2, SM2.N)) % SM2.N
    print(f"原始私钥: {d}")
    print(f"恢复私钥: {d_recovered}")
    print(f"验证结果: {d == d_recovered}")

    # 2. 不验证r,s范围的攻击
    print("\n2. 不验证r,s范围的攻击:")
    _, P = SM2.generate_key_pair()
    msg = b"important message"

    # 构造恶意签名 (r=0, s=0)
    malicious_sig = (0, 0)
    print("验证恶意签名(0,0):", SM2.verify(P, msg, malicious_sig))

    # 3. 不验证公钥在曲线上的攻击
    print("\n3. 无效公钥攻击:")
    # 生成一个不在曲线上的点
    invalid_P = (SM2.Gx + 1, SM2.Gy)
    msg = b"test message"
    sig = SM2.sign(d, msg)
    print("验证无效公钥:", SM2.verify(invalid_P, msg, sig))


# ==================== 伪造中本聪签名 ====================
def forge_satoshi_signature():
    """伪造中本聪签名演示"""
    print("\n=== 伪造中本聪签名 ===")

    # 中本聪的公钥 (示例)
    satoshi_pubkey = (0x75107B9F4B18B9D1F, 0x2A1CB8F1AB6A1A87)

    # 要伪造签名的消息
    message = b"Bitcoin is a great invention"

    # 方法1: 选择一个随机r，然后计算s使验证通过
    print("方法1: 选择随机r计算s")
    r = random.randint(1, SM2.N - 1)
    e = SM2._hash(message)
    t = random.randint(1, SM2.N - 1)

    # 计算伪造的s
    R = SM2._point_mul(t, satoshi_pubkey)
    R = SM2._point_add(SM2._point_mul(r, SM2.G), R)
    s = (t - r * e) % SM2.N

    forged_sig = (r, s)
    print(f"伪造签名: {forged_sig}")
    print("验证结果:", SM2.verify(satoshi_pubkey, message, forged_sig))

    # 方法2: 利用签名算法特性构造特殊签名
    print("\n方法2: 构造特殊签名")
    e = SM2._hash(message)
    r = (e + SM2.Gx) % SM2.N
    s = SM2._mod_inv(1 + SM2.Gx, SM2.N) * (SM2.Gy - r * SM2.Gx)) %SM2.N
    forged_sig = (r, s)
    print(f"伪造签名: {forged_sig}")
    print("验证结果:", SM2.verify(satoshi_pubkey, message, forged_sig))

    # ==================== 性能优化测试 ====================


def test_performance_optimizations():
    """测试SM2性能优化"""
    print("\n=== SM2性能优化测试 ===")

    # 预计算优化
    class SM2_Optimized(SM2):
        """优化版SM2实现"""

        # 预计算一些常用点
        _precomputed = {
            1: G,
            2: _point_add(G, G),
            4: _point_add(_point_add(G, G), _point_add(G, G))
        }

        @classmethod
        def _point_mul(cls, k: int, P: Tuple[int, int]) -> Tuple[int, int]:
            """优化后的点乘法"""
            # 使用预计算值
            if P == cls.G and k in cls._precomputed:
                return cls._precomputed[k]

            # 使用NAF表示法优化
            naf = []
            while k > 0:
                if k % 2 == 1:
                    naf.append(2 - (k % 4))
                    k = k - naf[-1]
                else:
                    naf.append(0)
                k = k // 2

            R = (0, 0)
            for i in reversed(naf):
                R = cls._point_add(R, R)
                if i > 0:
                    R = cls._point_add(R, P)
                elif i < 0:
                    R = cls._point_add(R, (P[0], -P[1] % cls.P))
            return R

    # 性能对比
    import time

    d, P = SM2.generate_key_pair()
    msg = b"test message"

    # 基础实现
    start = time.time()
    for _ in range(10):
        SM2.sign(d, msg)
    basic_time = time.time() - start

    # 优化实现
    start = time.time()
    for _ in range(10):
        SM2_Optimized.sign(d, msg)
    opt_time = time.time() - start

    print(f"基础实现签名时间(10次): {basic_time:.4f}s")
    print(f"优化实现签名时间(10次): {opt_time:.4f}s")
    print(f"加速比: {basic_time / opt_time:.2f}x")


# ==================== 主程序 ====================
if __name__ == "__main__":
    # SM2基础功能测试
    print("=== SM2基础功能测试 ===")
    d, P = SM2.generate_key_pair()
    print(f"私钥: {hex(d)}")
    print(f"公钥: ({hex(P[0])}, {hex(P[1])})")

    msg = b"Hello SM2"
    signature = SM2.sign(d, msg)
    print(f"\n消息: {msg}")
    print(f"签名: (r={hex(signature[0])}, s={hex(signature[1])})")
    print("验证结果:", SM2.verify(P, msg, signature))

    # 运行所有测试
    test_signature_misuse()
    forge_satoshi_signature()
    test_performance_optimizations()