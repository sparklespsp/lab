import random
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
import math


class PrivateIntersectionSum:
    def __init__(self):
        # 初始化，选择NIST推荐的P-256曲线（prime256v1）
        self.curve = ec.SECP256R1()
        # 使用SHA256作为哈希算法
        self.hash_algorithm = hashes.SHA256()

        # Paillier加密的参数设置
        self.paillier_key_size = 768  # 密钥长度（位）
        self.paillier_keys = self._generate_paillier_keys()

    def _generate_paillier_keys(self):
        # 简化版的Paillier密钥生成
        p = getPrime(self.paillier_key_size // 2)
        q = getPrime(self.paillier_key_size // 2)
        n = p * q
        g = n + 1  # g的简单选择
        lambda_val = (p - 1) * (q - 1)
        mu = pow(lambda_val, -1, n)

        return {
            'public': {'n': n, 'g': g},
            'private': {'lambda': lambda_val, 'mu': mu}
        }

    def _hash_to_curve(self, item):
        """将一个元素映射到椭圆曲线上的点"""
        # 使用HKDF进行哈希（简化版）
        hkdf = HKDF(
            algorithm=self.hash_algorithm,
            length=32,
            salt=None,
            info=b'hash_to_curve',
            backend=default_backend()
        )
        digest = hkdf.derive(item.encode())

        # 将哈希值转为曲线上的点（简化处理）
        x = int.from_bytes(digest, 'big') % self.curve.key_size
        return x

    def _encrypt_paillier(self, plaintext):
        """简化版Paillier加密"""
        n = self.paillier_keys['public']['n']
        g = self.paillier_keys['public']['g']
        r = random.randint(1, n - 1)  # 生成随机数r
        ciphertext = (pow(g, plaintext, n * n) * pow(r, n, n * n)) % (n * n)
        return ciphertext

    def _decrypt_paillier(self, ciphertext):
        """简化版Paillier解密"""
        n = self.paillier_keys['public']['n']
        lambda_val = self.paillier_keys['private']['lambda']
        mu = self.paillier_keys['private']['mu']

        x = pow(ciphertext, lambda_val, n * n)
        l = (x - 1) // n
        plaintext = (l * mu) % n
        return plaintext

    def _homomorphic_add(self, ciphertext1, ciphertext2):
        """Paillier加密的同态加法操作"""
        n = self.paillier_keys['public']['n']
        return (ciphertext1 * ciphertext2) % (n * n)

    def _generate_random_exponent(self):
        """生成用于离散对数运算的随机指数"""
        return random.randint(1, self.curve.key_size - 1)

    def client_round1(self, client_items):
        """协议的客户端第一轮"""
        k1 = self._generate_random_exponent()  # 客户端的随机指数
        hashed_items = []

        for item in client_items:
            # 将元素映射到曲线上
            x = self._hash_to_curve(item)
            # 使用客户端的随机指数进行指数运算
            y = pow(x, k1, self.curve.key_size)
            hashed_items.append(y)

        # 随机打乱顺序
        random.shuffle(hashed_items)

        return {
            'hashed_items': hashed_items,  # 哈希后的元素
            'k1': k1  # 客户端的随机指数
        }

    def server_round2(self, server_items_with_values, client_hashed_items):
        """协议的服务器第二轮"""
        k2 = self._generate_random_exponent()  # 服务器的随机指数
        double_hashed_items = []
        encrypted_values = []

        for item, value in server_items_with_values:
            # 将服务器的元素映射到曲线上
            x = self._hash_to_curve(item)
            # 使用服务器的随机指数进行指数运算
            y1 = pow(x, k2, self.curve.key_size)

            # 对元素的关联值进行加密
            encrypted_value = self._encrypt_paillier(value)

            double_hashed_items.append(y1)
            encrypted_values.append(encrypted_value)

        # 随机打乱顺序
        combined = list(zip(double_hashed_items, encrypted_values))
        random.shuffle(combined)
        double_hashed_items, encrypted_values = zip(*combined)

        # 对客户端的哈希值进行第二次指数运算
        client_double_hashed = [
            pow(item, k2, self.curve.key_size) for item in client_hashed_items
        ]

        return {
            'double_hashed_items': double_hashed_items,  # 双重哈希的服务器元素
            'encrypted_values': encrypted_values,  # 加密的关联值
            'client_double_hashed': client_double_hashed,  # 双重哈希的客户端元素
            'k2': k2  # 服务器的随机指数
        }

    def client_round3(self, client_items, k1, server_double_hashed,
                      server_encrypted_values, client_double_hashed):
        """协议的客户端第三轮，计算交集和"""
        # 计算客户端元素的双重哈希值
        our_double_hashed = []
        for item in client_items:
            x = self._hash_to_curve(item)
            y = pow(x, k1, self.curve.key_size)
            our_double_hashed.append(y)

        # 找到交集的索引
        intersection_indices = []
        for i, item in enumerate(our_double_hashed):
            if item in client_double_hashed:
                # 在服务器列表中找到索引
                idx = client_double_hashed.index(item)
                intersection_indices.append(idx)

        # 对交集中的值进行同态加法求和
        sum_ciphertext = self._encrypt_paillier(0)  # 加法的单位元素
        for idx in intersection_indices:
            sum_ciphertext = self._homomorphic_add(
                sum_ciphertext,
                server_encrypted_values[idx]
            )

        return {
            'intersection_size': len(intersection_indices),  # 交集的大小
            'encrypted_sum': sum_ciphertext  # 加密后的求和结果
        }

    def server_decrypt_sum(self, encrypted_sum):
        """服务器解密最终的求和结果"""
        return self._decrypt_paillier(encrypted_sum)


# 示例程序
def example_usage():
    protocol = PrivateIntersectionSum()

    # 客户端数据 - 如密码列表
    client_data = ["password123", "securePass", "admin123", "qwerty"]

    # 服务器数据 - 密码及泄露次数
    server_data = [
        ("password123", 15000),
        ("123456", 500000),
        ("qwerty", 250000),
        ("admin", 10000)
    ]

    # 协议执行过程

    # 客户端第一轮
    client_round1_result = protocol.client_round1(client_data)
    print(f"客户端第一轮完成 - 发送了{len(client_round1_result['hashed_items'])}个哈希值")

    # 服务器第二轮
    server_round2_result = protocol.server_round2(
        server_data,
        client_round1_result['hashed_items']
    )
    print("服务器第二轮完成 - 发送了双重哈希的元素和加密值")

    # 客户端第三轮
    client_round3_result = protocol.client_round3(
        client_data,
        client_round1_result['k1'],
        server_round2_result['double_hashed_items'],
        server_round2_result['encrypted_values'],
        server_round2_result['client_double_hashed']
    )
    print(f"客户端第三轮完成 - 交集大小: {client_round3_result['intersection_size']}")

    # 服务器解密求和结果
    sum_breach_counts = protocol.server_decrypt_sum(client_round3_result['encrypted_sum'])
    print(f"服务器解密后的泄露次数求和: {sum_breach_counts}")

    # 验证交集是否正确
    intersection = set(client_data) & {item[0] for item in server_data}
    actual_sum = sum(count for item, count in server_data if item in intersection)
    print(f"实际交集: {intersection}, 求和: {actual_sum}")
    print(f"协议正确性: {sum_breach_counts == actual_sum}")


if __name__ == "__main__":
    example_usage()