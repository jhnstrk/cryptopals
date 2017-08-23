#include "testSet6_dsa.h"

#include <qbigint.h>
#include <dsa.h>
#include <utils.h>

#include <QDebug>
#include <QCryptographicHash>
#include <QTest>

#include "test.h"

JDS_ADD_TEST(TestSet6_Dsa)
namespace {
    const char * const p43 = "800000000000000089e1855218a0e7dac38136ffafa72eda7"
            "859f2171e25e65eac698c1702578b07dc2a1076da241c76c6"
            "2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe"
            "ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2"
            "b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87"
            "1a584471bb1";

    const char * const q43 = "f4f47f05794b256174bba6e9b396a7707e563c5b";

    const char * const g43 = "5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119"
            "458fef538b8fa4046c8db53039db620c094c9fa077ef389b5"
            "322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047"
            "0f5b64c36b625a097f1651fe775323556fe00b3608c887892"
            "878480e99041be601a62166ca6894bdd41a7054ec89f756ba"
            "9fc95302291";

    QByteArray sha1Hash(const QByteArray & data) {
        return QCryptographicHash::hash(data, QCryptographicHash::Sha1);
    }
}

void TestSet6_Dsa::testBasicDsa()
{
    Dsa::Parameters param;
    param.g = QBigInt::fromString(g43,16);
    param.p = QBigInt::fromString(p43,16);
    param.q = QBigInt::fromString(q43,16);

    const Dsa::KeyPair key = Dsa::dsaKeyGen(param);

    const QByteArray messageHash = sha1Hash("Hello World");

    Dsa::Signature sig = Dsa::signHash(key.second, messageHash);

    // Genuine signature: OK
    QVERIFY( Dsa::verifyMessageSignature(key.first, sig, messageHash) );

    // Bad message: Not OK
    const QByteArray otherHash = sha1Hash("Not World");
    QVERIFY(!Dsa::verifyMessageSignature(key.first, sig, otherHash) );

    // Sign with another (valid) key.
    const Dsa::KeyPair otherKey = Dsa::dsaKeyGen(param);
    const Dsa::Signature otherSig = Dsa::signHash(otherKey.second, messageHash);

    // Veriying first signature against the second key fails
    QVERIFY( !Dsa::verifyMessageSignature(otherKey.first, sig, messageHash) );

    // Veriying second signature against the first key fails
    QVERIFY( !Dsa::verifyMessageSignature(key.first, otherSig, messageHash) );

    // Veriying second signature against the second key succeeds
    QVERIFY( Dsa::verifyMessageSignature(otherKey.first, otherSig, messageHash) );
}
