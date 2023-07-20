# Ciphertools

A simple library for basic cybersecurity algorithms.

## Usage

This library is not for real cybersecurity use. Tools
inside here are not complicated and fast enough for that 
use. But this is a simple and fast enough library for 
small projects that requires a tint of security. It creates
a bundle for ciphering, a little all-in-one. It has prime
number generation functions, a hash function, RSA keygen
function and encryption-decryption functions for RSA.

No useful initialization occurs in this class, creating a
ciphertools object just prints the _dir()_ function of the
class.

### hash(str)

Just an analogue of md5. Output is made of all the new internal
state numbers, not just the last one. Pretty much only difference
is that. Return is a string.

### primeByOrder(int)

Takes an integer as the order, then returns the prime in the order.
Useful for generating large primes by just inputting their order.
Default argument is a random 8-bit number plus one, in case 0 is
choosen. If the argument is smaller than 1, raises RangeError.

### primeByRange(int, int)

Returns a list of primes in given range. If the range is invalid, 
raises a RangeError.

### isPrime(int)

Returns true if the argument is a prime. If the argument is smaller
than 2, returns false.

### keygenRsa(p, q, smallest)

Creates a tuple of public and private key and returns it. Public key
is itself a tuple. p and q as primes can be given. _smallest_ determines 
the e. If true, which is the default, e is the smallest number possible. 
If false, e is choosen randomly within the list. If randomly choosen, 
private key generation takes a lot of time, therefore the default is true.

If given p and q are not primes, raises an ArgError.

### encryptorRsa(public, message)

Takes in the public key and the message, then encrypts the message. Returns
the encrypted message as a tuple. Every element in this tuple represents a
character.

### decryptorRsa(public, private, message)

Takes in the keys and the encrypted message, then returns the decrypted message.
Return type is string this time.
