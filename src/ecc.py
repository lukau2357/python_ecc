import tinyec.registry as reg
import tinyec.ec as ec
import secrets

from typing import Tuple, Union

def ecc_add(p : int, a : float, P : Union[None, Tuple[float]], Q : Union[None, Tuple[float]]) -> Union[None, Tuple[float]]:
    if P is None:
        return Q
    
    if Q is None:
        return P
    
    x1 = P[0]
    y1 = P[1]

    x2 = Q[0]
    y2 = Q[1]

    if x1 == x2 and y1 == -y2:
        return None

    Lambda = ((y2 - y1) * pow((x2 - x1) % p, -1, p)) % p if P != Q else ((3 * pow(x1, 2, p) + a) * pow((2 * y1) % p, -1, p)) % p
    x3 = (pow(Lambda, 2, p) - x1 - x2) % p
    y3 = (Lambda * (x1 - x3) - y1) % p

    return (x3, y3)

def double_and_add(p : int, a : float, n : int, P : Union[None, Tuple[float]]) -> Union[None, Tuple[float]]:
    Q = P
    R = None

    while n > 0:
        if n % 2 == 1:
            R = ecc_add(p, a, R, Q)
        
        Q = ecc_add(p, a, Q, Q)
        n //= 2
    
    return R

if __name__ == "__main__":
    ECC_STANDARDS = {
        "secp256k1": {
            "p": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
            "a": 0,
            "b": 7,
            "G": (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8),
            "order_G": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
            "url": "https://en.bitcoin.it/wiki/Secp256k1",
            "Trivia": "Used for signing Bitcoin transactions"
        },

        "brainpoolP256r1": {
            "p": 0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377,
            "a": 0x7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9,
            "b": 0x26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6,
            "G": (0x8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262, 0x547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997),
            "order_G": 0xa9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7,
            "url": "https://neuromancer.sk/std/brainpool/brainpoolP256r1#"
        },

        "nistp256": {
            "p": 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
            "a": 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc,
            "b": 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
            "G": (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5),
            "order_G": 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
            "url": "https://neuromancer.sk/std/nist/P-256#"
        }
    }

    curve = reg.get_curve("brainpoolP256r1")
    G = curve.g
    g = (G.x, G.y)

    print(G.y)
    print(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F % 4)
    print(0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377 % 4)
    print(0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff % 4)
    
    primes = [0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F, 0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377, 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff]

    for prime in primes:
        Y_squared = pow(G.y, 2, prime)
        Y_sqrt = pow(Y_squared, (prime + 1) // 4, prime)
        print((G.y == Y_sqrt) or (G.y == (-Y_sqrt) % prime))

    exit(0)
    G_ord = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    ephermal_a = secrets.randbelow(G_ord)
    ephermal_b = secrets.randbelow(G_ord)

    transit_a = ephermal_a * G
    transit_b = ephermal_b * G

    secret_a = transit_b * ephermal_a
    secret_b = transit_a * ephermal_b

    Transit_a = double_and_add(G.p, curve.a, ephermal_a, g)
    Transit_b = double_and_add(G.p, curve.a, ephermal_b, g)
    Secret_a = double_and_add(G.p, curve.a, ephermal_a, Transit_b)
    Secret_b = double_and_add(G.p, curve.a, ephermal_b, Transit_a)

    print(secret_a == secret_b)
    print(Secret_a == Secret_b)
    print(Secret_a[0] == secret_a.x)
    print(Secret_a[1] == secret_a.y)

    print(Secret_a)
    print((secret_a.x, secret_a.y))