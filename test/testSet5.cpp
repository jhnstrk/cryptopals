#include "testSet5.h"

#include <utils.h>
#include <sha_1.h>
#include <qbigint.h>

#include <QByteArray>
#include <QDebug>
#include <QElapsedTimer>
#include <QThread>
#include <QTest>

#include "test.h"

JDS_ADD_TEST(TestSet5)

namespace {
    const char * const nist_p = 
            "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
            "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
            "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
            "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
            "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
            "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
            "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
            "fffffffffffff";
}
void TestSet5::initTestCase()
{

}

void TestSet5::cleanupTestCase()
{

}

namespace {
    quint64 mod_exp(quint64 x, quint64 p, quint64 m)
    {
        if (p == 0) {
            return 1;
        }
        if (m <= 1) {
            return 0;
        }
        quint64 y = x;
        for (quint64 i = 1; i < p; ++i) {
            y *= x;
            y = y % m;
        }
        return y;
    }

    QBigInt randomValue(const QBigInt & mx)
    {
        return QBigInt( qossl::randomBytes(mx.highBitPosition() / CHAR_BIT + 1) ) % mx;
    }
}

void TestSet5::testChallenge33_1()
{
    // Set a variable "p" to 37 and "g" to 5.
    const quint64 p = 37;
    const quint64 g = 5;

    // Generate "a", a random number mod 37.
    quint64 a = qossl::randomUInt() % p;

    // Now generate "A", which is "g" raised to the "a" power mode 37 --- A = (g**a) % p.
    quint64 A = mod_exp(g,a,p);

    // Do the same for "b" and "B".
    quint64 b = qossl::randomUInt() % p;
    quint64 B = mod_exp(g,b,p);

    // "A" and "B" are public keys. Generate a session key with them;
    // set "s" to "B" raised to the "a" power mod 37 --- s = (B**a) % p.
    quint64 s = mod_exp(B,a,p);

    // Do the same with A**b, check that you come up with the same "s".
    quint64 s_a = mod_exp(A,b,p);

    QCOMPARE( s, s_a);

    // To turn "s" into a key, you can just hash it to create 128 bits
    // of key material (or SHA256 it to create a key for encrypting and a key for a MAC).
    QByteArray s_key = qossl::Sha1::hash(QByteArray::number(s, 16));
    QVERIFY(!s_key.isNull());
}

void TestSet5::testChallenge33_2()
{
    const QBigInt p( QString(nist_p) , 16);
    const QBigInt g(5);

    // Generate "a", a random number mod p.
    QBigInt a = randomValue(p);

    // Now generate "A", which is "g" raised to the "a" power mode 37 --- A = (g**a) % p.
    QBigInt A = g.modExp(a,p);

    // Do the same for "b" and "B".
    QBigInt b = randomValue(p);
    QBigInt B = g.modExp(b,p);

    // "A" and "B" are public keys. Generate a session key with them;
    // set "s" to "B" raised to the "a" power mod p --- s = (B**a) % p.
    QBigInt s = B.modExp(a,p);

    // Do the same with A**b, check that you come up with the same "s".
    QBigInt s_a = A.modExp(b,p);

    QCOMPARE( s.toString(16), s_a.toString(16) );

    // To turn "s" into a key, you can just hash it to create 128 bits
    // of key material (or SHA256 it to create a key for encrypting and a key for a MAC).
    QByteArray s_key = qossl::Sha1::hash(s.toLittleEndianBytes());
    QVERIFY(!s_key.isNull());
}

void TestSet5::testChallenge34_1()
{

}
