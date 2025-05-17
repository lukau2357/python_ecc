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