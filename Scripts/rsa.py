import Crypto.Util.number
from Crypto.Util.number import long_to_bytes, bytes_to_long

# encryption
def find_N(p, q):
    return p * q

# encrypt message m using e and modulus N
def encrypt(m, e, N):
    return pow(m, e, N)

# find decryption key given encryption key (e and prime numbers p and q)
def find_d(e, p, q):
    return pow(e, -1, (p - 1) * (q - 1))

# decrypt message m given decryption key d and modulus N
def decrypt(m, d, N):
    return pow(m, d, N)

# RSA decryption for e=3 and given 3 ciphertexts + 3 moduli
def simpleRSA(c1, c2, c3, n1, n2, n3):
    big_N = n1 * n2 * n3
    ciphers = [c1, c2, c3]
    new_mods = [big_N // n1, big_N // n2, big_N // n3]
    mods = [n1, n2, n3]
    inverses = []   

    for i in range(3):
        inverses.append(modular_mult_inverse(new_mods[i], mods[i]))
    return cube_root_finder(chinese_remainder_theorem(ciphers, new_mods, inverses, big_N))

# finds cube root of num
def cube_root_finder(num):
    low = 0
    high = num

    while low < high:
        mid = (low + high) // 2
        if mid ** 3 < num:
            low = mid + 1
        elif mid ** 3 > num:
            high = mid
        else:
            return mid
    return mid

# returns modular multiplicative inverse of a mod N
def modular_mult_inverse(a, N):
    return pow(a, -1, N)

# chinese remainder theorem to find plaintext message m^3 given that e=3
def chinese_remainder_theorem(ciphers, mods, inverses, bigN):
    sum = 0
    for i in range(3):
        sum += ciphers[i] * mods[i] * inverses[i]
    return sum % bigN

# prime numbers to make N
p = 336133654835868603442558046100231888821
q = 318124025086734517255758234170895923393

# ciphertext
c1 = 74597365847504917912916866838569123286395165031450770943853702985527537374325
c2 = 7392488009685177703766329111985085924328495872306844961776805115046085005730
c3 = 21070202880950860480001393449893080177749578386435659153510821967923393222435

# moduli
n1 = 92654857070767571890017042106637703986449117869087364338047922606069735162919
n2 = 98572474388371800971130449337009030864118807314878868777502700832091542642841
n3 = 51501476121983355743052534942567218556170618226963749616587274414221577824191

# public encryption key
e = 3

# use when given p and q
# N = find_N(p, q)
# d = find_d(e, p, q)

# use when given e but not p and q
# print(long_to_bytes(simpleRSA(c1, c2, c3, n1, n2, n3)))