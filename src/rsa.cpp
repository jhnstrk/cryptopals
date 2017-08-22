#include "rsa.h"

#include "utils.h"

namespace Rsa {

QBigInt encrypt(const Rsa::PubKey &key, const QBigInt &m) {
    return m.modExp(key.e,key.n);
}

QBigInt decrypt(const PrivKey &key, const QBigInt &c) {
    return c.modExp(key.d,key.n);
}

KeyPair rsaKeyGen(int bits) {
    //    Generate 2 random primes. ... Call them "p" and "q".
    const QBigInt p = QBigInt::fromBigEndianBytes(qossl::primeGen(bits));
    const QBigInt q = QBigInt::fromBigEndianBytes(qossl::primeGen(bits));
    //    Let n be p * q. Your RSA math is modulo n.
    const QBigInt n = p*q;
    //    Let et be (p-1)*(q-1) (the "totient"). You need this value only for keygen.
    const QBigInt et = (p-1)*(q-1);
    //    Let e be 3.
    const QBigInt e(3);
    //    Compute d = invmod(e, et).
    const QBigInt d = QBigInt::invmod(e,et);
    //    Your public key is [e, n]. Your private key is [d, n].
    PubKey pub;
    pub.e = e;
    pub.n = n;

    PrivKey priv;
    priv.d = d;
    priv.n = n;
    return KeyPair(pub,priv);
}

} // Rsa
