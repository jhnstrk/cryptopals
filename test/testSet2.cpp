#include "testSet2.h"

#include <utils.h>

#include <QByteArray>
#include <QDebug>
#include "test.h"

#include <algorithm>

JDS_ADD_TEST(TestSet2)

void TestSet2::initTestCase()
{

}

void TestSet2::cleanupTestCase()
{

}

void TestSet2::testPkcs7Pad_data()
{
    QTest::addColumn<QByteArray>("data");
    QTest::addColumn<int>("len");
    QTest::addColumn<QByteArray>("padded");

    QTest::newRow("Challenge1")
        << QByteArray("YELLOW SUBMARINE")
        << 20
        <<  QByteArray("YELLOW SUBMARINE\x04\x04\x04\x04");

    QTest::newRow("short")
        << QByteArray("1") << 5 << QByteArray("1\x04\x04\x04\x04");
    QTest::newRow("no pad char")
        << QByteArray("YELLOW SUBMARINE") << 16 << QByteArray("YELLOW SUBMARINE");
    QTest::newRow("empty")
        << QByteArray("") << 16 << QByteArray("");
    QTest::newRow("2 blocks")
        << QByteArray("12345") << 4 << QByteArray("12345\x03\x03\x03");
}

void TestSet2::testPkcs7Pad()
{
    const QFETCH( QByteArray, data);
    const QFETCH( int, len);
    const QFETCH( QByteArray, padded);

    const QByteArray actual = qossl::pkcs7Pad(data,len);

    QCOMPARE(actual, padded);
}

void TestSet2::testAesEcbEncrypt_data()
{
    QTest::addColumn<QByteArray>("data");
    QTest::addColumn<QByteArray>("key");

    QTest::newRow("Simple")
        << QByteArray("xygxygyxgxygxygvxygxygyxgxygxygvxygxygyxgxygxygv")
        << QByteArray("YELLOW SUBMARINE");
}

void TestSet2::testAesEcbEncrypt()
{
    const QFETCH( QByteArray, data);
    const QFETCH( QByteArray, key);

    const QByteArray cipherText = qossl::aesEcbEncrypt(data,key);
    const QByteArray plainText = qossl::aesEcbDecrypt(cipherText,key);

    // Decrypting should recover data.
    QCOMPARE(plainText, data);
}
