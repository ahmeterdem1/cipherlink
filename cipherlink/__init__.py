import math
import secrets

class RangeError(Exception):
    def __init__(self):
        super().__init__("Arguments off range")

class ArgError(Exception):
    def __init__(self, control: int):
        if control == 0:
            super().__init__("Args must be primes")

class cipherlink:

    def __init__(self):
        print(dir(cipherlink))

    def hash(text: str):
        temp = ""
        for k in text:
            temp += str(bin(ord(k)))
        temp = temp.replace("b", "")  # gets 8 bit ascii numbers in a string, has the reduced net length of the message
        length = bin(len(text))  # LENGTH IN BINARY
        length = str(length.replace("0b", ""))  # deletes the first 0b from the string
        length_of_length = len(length)
        padding = 64 - length_of_length
        if len(temp) < 512:
            remainder = 512 - len(temp)
        else:
            remainder = len(temp) % 512
        temp += "1"
        temp += "0" * (remainder - 1)  # temp is prepared without the length part
        temp += "0" * padding
        temp += length  # now it is fully prepared

        J = 0x67425301
        K = 0xEDFCBA45
        L = 0x98CBADFE
        M = 0x13DCE476

        def F(K, L, M, J):
            L += M
            result = (K and L) or (not K and M)
            L += result
            L = L << 1
            return L % (pow(2, 32))

        def G(K, L, M, J):
            result = (K and L) or (L and not M)
            M += result
            M = M << 1
            return M % (pow(2, 32))

        def H(K, L, M, J):
            J += M
            result = K ^ L ^ M
            J += result
            J = J << 1
            return J % (pow(2, 32))

        def I(K, L, M, J):
            K += M
            result = L ^ (K or not M)
            K += result
            K = K << 1
            return K % (pow(2, 32))

        l = 0
        for k in range(0, 16):
            message = ""
            for m in range(l, l + 32):  # prepares the message
                message += temp[m]
            l += 32
            message = int(message, 2)
            M = (M + message) % pow(2, 32)
            L = F(K, L, M, J)

        l = 0
        for k in range(0, 16):
            message = ""
            for m in range(l, l + 32):  # prepares the message
                message += temp[m]
            l += 32
            message = int(message, 2)
            M = (M + message) % pow(2, 32)
            M = G(K, L, M, J)

        l = 0
        for k in range(0, 16):
            message = ""
            for m in range(l, l + 32):  # prepares the message
                message += temp[m]
            l += 32
            message = int(message, 2)
            M = (M + message) % pow(2, 32)
            J = H(K, L, M, J)

        l = 0
        for k in range(0, 16):
            message = ""
            for m in range(l, l + 32):  # prepares the message
                message += temp[m]
            l += 32
            message = int(message, 2)
            M = (M + message) % pow(2, 32)
            K = I(K, L, M, J)

        return str(J).replace("0x", "") + str(K).replace("0x", "") + str(L).replace("0x", "") + str(M).replace("0x", "")

    def gcd(a: int, b: int):
        if a == 0:
            return b
        if a > b:
            return cipherlink.gcd(a%b, b)
        return cipherlink.gcd(b%a, a)

    def gcdExtended(a: int, b: int):
        if not b > a:
            return cipherlink.gcdExtended(b, a)
        if a == 0:
            return b, 0, 1
        gcd, s1, t1 = cipherlink.gcdExtended(b%a, a)

        s, t = (t1 - b//a * s1, s1)
        return gcd, s, t

    def primeByOrder(order: int = secrets.randbits(8) + 1):
        if order < 1:
            raise RangeError
        temp = [2]
        a = 3
        while len(temp) < order:
            for k in temp:
                if a % k == 0:
                    break
                elif k == temp[-1]:
                    temp.append(a)
                    break
            a += 1
        return temp[-1]

    def primeByRange(begin: int = 2, end: int = 2):
        if begin < 2:
            begin = 2
        if begin > end:
            raise RangeError
        if begin > 2:
            temp = cipherlink.primeByRange(2, begin)
        else:
            temp = [2]
        l = len(temp)
        a = begin
        while begin < end:
            for k in temp:
                if begin % k == 0:
                    break
                elif k == temp[-1]:
                    temp.append(begin)
                    break
            begin += 1
        if a == end:
            return temp
        return temp[l:]

    def isPrime(value: int):
        if value < 2:
            return False
        for k in range(2, math.floor(math.sqrt(value))):
            if value % k == 0:
                return False
        return True

    def keygenRsa(p: int = 0, q: int = 0, smallest: bool = True):
        if p == 0 and q == 0:
            p = cipherlink.primeByRange(3000, 5000)
            p = p[secrets.randbits(32) % len(p)]
            q = cipherlink.primeByRange(3000, 5000)
            q = q[secrets.randbits(32) % len(q)]

        if not (cipherlink.isPrime(p) and cipherlink.isPrime(q)):
            raise ArgError(0)
        #phi = int(((p - 1) * (q - 1)) / cipherlink.gcd(p - 1, q - 1))
        #using this sometimes results in a ValueError in decryptor, probably because of the division here
        #so i am not implementing it
        phi = (p - 1) * (q - 1)
        n = p * q
        e_list = list()

        for a in range(2, phi):
            if not (phi / a == phi // a):
               e_list.append(a)
        if smallest:
            e = e_list[0]
        else:
            e = e_list[secrets.randbits(32) % len(e_list)]
        del e_list

        gcd, x, y = cipherlink.gcdExtended(e, phi)
        if (x * e) % phi == 1:
            d = x
        else:
            d = y
        while d < 2:
            d += phi

        return ((n, e), d)

    def encryptorRsa(public: tuple, message: str):
        result = list()
        for k in message:
            value = ord(k)
            temp = 1
            for l in range(public[1]):
                temp *= value
                temp = temp % public[0]
            result.append(temp)
        return tuple(result)

    def decryptorRsa(public: tuple, private: int, message: tuple):
        result = ""
        for k in message:
            value = k
            temp = 1
            for l in range(private):
                temp *= value
                temp = temp % public[0]
            result += chr(temp)
        return result

    def encryptorRsa2(public: tuple, message: str):
        # it is beneficial to put the message in r"" form
        # otherwise characters that have no visualisation
        # will break the process since they are unrecognized
        result = list()
        groups = list()
        temp = list(message)

        if len(temp) % 2 == 0:
            for k in range(0, len(temp), 2):
                groups.append(int(str(ord(temp[k])) + str(ord(temp[k + 1]))))
        else:
            for k in range(0, len(temp), 2):
                if k == len(temp) - 1:
                    groups.append(int(str(ord(temp[-1]))))
                    break
                groups.append(int(str(ord(temp[k])) + str(ord(temp[k + 1]))))
        del temp

        for k in groups:
            temp = 1
            for l in range(public[1]):
                temp = temp % public[0]
                temp *= k
            temp = temp % public[0]
            result.append(temp)
        return tuple(result)

    def decryptorRsa2(public: tuple, private: int, message: tuple):
        result = ""
        result2 = list()
        for k in message:
            temp = 1
            for l in range(private):
                temp = temp % public[0]
                temp *= k
            temp = temp % public[0]
            result2.append(str(temp))
        for k in result2:
            value = k
            while int(value) >= 128:
                value = value[:-1]
            result += chr(int(value))
            if len(k) > 3:
                value2 = k[len(value):]
                result += chr(int(value2))

        return result

