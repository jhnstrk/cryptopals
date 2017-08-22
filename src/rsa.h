#pragma once

#include "qbigint.h"

namespace Rsa {

struct PrivKey {
    QBigInt d,n;
};
struct PubKey {
    QBigInt e,n;
};

typedef QPair<PubKey, PrivKey> KeyPair;

KeyPair rsaKeyGen(int bits);

QBigInt encrypt(const PubKey & key, const QBigInt & m);
QBigInt decrypt(const PrivKey & key, const QBigInt & c);
}
