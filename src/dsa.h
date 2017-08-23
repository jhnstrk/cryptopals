#pragma once

#include "qbigint.h"

namespace Dsa {

struct Parameters {
    QBigInt g,p,q;
};

struct PubKey {
    QBigInt y;
    Parameters param;
};

struct PrivKey {
    QBigInt x;
    Parameters param;
};

typedef QPair<PubKey, PrivKey> KeyPair;

Parameters dsaParamGen(int bitsN, int bitsL);
KeyPair dsaKeyGen(const Parameters & param);

struct Signature {
    Signature() {}
    Signature(const QBigInt & r_, const QBigInt & s_) :
        r(r_),s(s_) {}

    QBigInt r;
    QBigInt s;
};

Signature signHash(const PrivKey & key, const QBigInt & m);
bool verifyMessageSignature(const PubKey & key, const Signature & s, const QBigInt & m);

}
