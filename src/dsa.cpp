#include "dsa.h"
#include "utils.h"

namespace Dsa {

Parameters dsaParamGen(int bitsN, int bitsL)
{
    const QBigInt q = QBigInt::fromBigEndianBytes(qossl::primeGen(bitsN));
    const QBigInt p = QBigInt::fromBigEndianBytes(qossl::primeGen(bitsL,q.toBigEndianBytes()));

    QBigInt g;
    QBigInt h = QBigInt(2);

    // Derive g, a number whose multiplicative order modulo p is q.
    const QBigInt r = (p - QBigInt(1)) / q;
    while(true) {
        g = h.powm(r,p);
        if (g > QBigInt::one()) {
            break;
        }
        ++h;
    }

    Parameters ret;
    ret.p = p;
    ret.q = q;
    ret.g = g;
    return ret;
}

KeyPair dsaKeyGen(const Parameters & param)
{
    const QBigInt & p = param.p;
    const QBigInt & q = param.q;
    const QBigInt & g = param.g;

    // Random number less than q
    const unsigned int numBytes = (q.highBitPosition() + 7) / 8;

    QBigInt x;
    do {
        x = QBigInt::fromBigEndianBytes(qossl::randomBytes(numBytes)) % q;
    } while (x.isZero()); // Unlikely.

    const QBigInt y = g.powm(x,p);

    KeyPair ret;
    ret.first.param = param;
    ret.first.y = y;
    ret.second.param = param;
    ret.second.x = x;
    return ret;
}

Signature signHash(const PrivKey & key, const QBigInt & Hm)
{
    const QBigInt & x = key.x;
    const QBigInt & p = key.param.p;
    const QBigInt & q = key.param.q;
    const QBigInt & g = key.param.g;

    // Random number less than q
    const unsigned int numBytes = (q.highBitPosition() + 7) / 8;

    while(true) {
       const QBigInt k = QBigInt::fromBigEndianBytes(qossl::randomBytes(numBytes)) % q;

       if (k < QBigInt(2)) {
           continue;
       }

       const QBigInt r = g.powm(k,p) % q;
       if (r.isZero()){
           continue;  // Also unlikely.
       }

       const QBigInt s = (QBigInt::invmod(k,q) * (Hm + x * r)) % q;
       if (s.isZero()) {
           continue;  // Also unlikely.
       }

       return Signature(r,s);
    }
    // Can never reach here;
}

bool verifyMessageSignature(const PubKey & key, const Signature & sig, const QBigInt &Hm){
    const QBigInt & r = sig.r;
    const QBigInt & s = sig.s;
    const QBigInt & y = key.y;
    const QBigInt & p = key.param.p;
    const QBigInt & q = key.param.q;
    const QBigInt & g = key.param.g;

    if ( !( QBigInt(0) < r ) ) {
        return false;
    }

    if ( !( r < q ) ) {
        return false;
    }

    if ( !( QBigInt(0) < s ) ) {
        return false;
    }

    if ( !( s < q ) ) {
        return false;
    }

    const QBigInt w = QBigInt::invmod(s,q);
    const QBigInt u1 = (Hm * w) % q;
    const QBigInt u2 = (r * w) % q;
    const QBigInt v = ( ( g.powm(u1,p) * y.powm(u2,p) ) % p ) % q;

    return v == r;
}

}
