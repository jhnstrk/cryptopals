#include "testSet5_rsa.h"

#include <qbigint.h>
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
    QTest::newRow("small primes") << 16 << QByteArray("X");
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
