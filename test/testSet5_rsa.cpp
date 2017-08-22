#include "testSet5_rsa.h"

#include <qbigint.h>
#include <rsa.h>
#include <utils.h>

#include <QDebug>
#include <QTest>

#include "test.h"

JDS_ADD_TEST(TestSet5_Rsa)

void TestSet5_Rsa::testPrimeGen()
{
    QByteArray bytes = qossl::primeGen(10); // A Small prime...

    QBigInt value = QBigInt::fromBigEndianBytes(bytes);
    qDebug() << "Prime is " << value;

    for (unsigned int i=2; i<value.toULongLong(); ++i) {
        QVERIFY( value % i != QBigInt::zero());
    }
}

void TestSet5_Rsa::testBasicRsa_data()
{
    QTest::addColumn<int>("primeBits");
    QTest::addColumn<QByteArray>("message");

    // Message must be less than primeBits bits in size.
    QTest::newRow("small primes") << 16 << QByteArray().append((char)42);
    QTest::newRow("bigger primes") << 512 << QByteArray("Hello");
    QTest::newRow("big primes") << 2048 << QByteArray("Hello World");
}

void TestSet5_Rsa::testBasicRsa()
{
    const QFETCH(int, primeBits);
    const QFETCH(QByteArray, message);

    //    Generate 2 random primes. ... Call them "p" and "q".
    const QBigInt p = QBigInt::fromBigEndianBytes(qossl::primeGen(primeBits));
    const QBigInt q = QBigInt::fromBigEndianBytes(qossl::primeGen(primeBits));
    //    Let n be p * q. Your RSA math is modulo n.
    const QBigInt n = p*q;
    //    Let et be (p-1)*(q-1) (the "totient"). You need this value only for keygen.
    const QBigInt et = (p-1)*(q-1);
    //    Let e be 3.
    const QBigInt e(3);
    //    Compute d = invmod(e, et).
    const QBigInt d = QBigInt::invmod(e,et);
    //    Your public key is [e, n]. Your private key is [d, n].

    //    To encrypt: c = m**e%n. To decrypt: m = c**d%n
    //    Test this out with a number, like "42".
    const QBigInt c = QBigInt::fromBigEndianBytes(message).modExp(e,n);

    // Decrypt...
    const QBigInt m = c.modExp(d,n);
    QCOMPARE(m.toBigEndianBytes(), message);
    //    Repeat with bignum primes (keep e=3).
}

namespace {

    using namespace Rsa;

    QByteArray broadcastAttack(const QBigInt & c_0,const QBigInt & c_1,const QBigInt & c_2,
                               const PubKey & pub0,const PubKey & pub1,const PubKey & pub2)
    {
        // Using the Chinese Remainder Theorem to solve for the texts.
        const QBigInt m_s_0 = pub1.n * pub2.n;
        const QBigInt m_s_1 = pub0.n * pub2.n;
        const QBigInt m_s_2 = pub0.n * pub1.n;
        const QBigInt N_012 = pub0.n * pub1.n * pub2.n; // is the product of all three moduli

        const QBigInt result =
                ((c_0 * m_s_0 * QBigInt::invmod(m_s_0, pub0.n)) +
                 (c_1 * m_s_1 * QBigInt::invmod(m_s_1, pub1.n)) +
                 (c_2 * m_s_2 * QBigInt::invmod(m_s_2, pub2.n))) % N_012;

        const QPair<QBigInt,QBigInt> rootRem = result.nthRootRem(3);
        const QBigInt &root(rootRem.first);
        const QBigInt &rem(rootRem.second);
        if (!rem.isZero()) {
            qDebug() << "Root not found" << rem.highBitPosition() << rem.isNegative();
            qDebug() << ((root * root * root) < result);
            qDebug() << (((root+QBigInt::one()) * (root+QBigInt::one()) * (root+QBigInt::one())) < result);
            qDebug() << ((root * root * root) + rem == result);
        }
        return rootRem.first.toBigEndianBytes();
    }
}
void TestSet5_Rsa::challenge40()
{
    const int keyBits = 512;
    KeyPair k0 = rsaKeyGen(keyBits);
    KeyPair k1 = rsaKeyGen(keyBits);
    KeyPair k2 = rsaKeyGen(keyBits);

    QByteArray plain = "Javascript is ace.";
    plain = plain.left((keyBits-1)/8);

    // Three cipher texts, same plain, different keys.
    const QBigInt c0 = encrypt(k0.first,QBigInt::fromBigEndianBytes(plain));
    const QBigInt c1 = encrypt(k1.first,QBigInt::fromBigEndianBytes(plain));
    const QBigInt c2 = encrypt(k2.first,QBigInt::fromBigEndianBytes(plain));

    if (k0.first.n == k1.first.n ||
            k0.first.n == k2.first.n ||
            k1.first.n == k2.first.n) {
        qWarning() << "Keys were the same";  // There's a finite chance of this.
        return;
    }
    QByteArray recoveredPlain = broadcastAttack(c0,c1,c2,k0.first, k1.first, k2.first);

    QCOMPARE( recoveredPlain, plain );
}
