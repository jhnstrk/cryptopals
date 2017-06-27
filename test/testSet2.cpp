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
        << QByteArray("YELLOW SUBMARINE") << 16 << QByteArray("YELLOW SUBMARINE").append(QByteArray(16,16));
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

void TestSet2::testAesCbcDecrypt_data()
{
    QTest::addColumn<QByteArray>("data");
    QTest::addColumn<QByteArray>("key");
    QTest::addColumn<QByteArray>("iv");
    QTest::addColumn<QByteArray>("startsWith");
    QTest::addColumn<QByteArray>("endsWith");

    QFile file(":/qossl_test_resources/rsc/set2/10.txt");
    QVERIFY(file.open(QIODevice::ReadOnly));
    const QByteArray cipherText = QByteArray::fromBase64(file.readAll());
    file.close();

    QTest::newRow("Challenge10") << cipherText
                                 << QByteArray("YELLOW SUBMARINE")
                                 << QByteArray(qossl::AesBlockSize,(char)0)
                                 << QByteArray("I'm back and I'm ringin' the bell \nA rockin' on")
                                 << QByteArray("Come on \nPlay that funky music \n");
}

void TestSet2::testAesCbcDecrypt()
{
    const QFETCH(QByteArray, data);
    const QFETCH(QByteArray, key);
    const QFETCH(QByteArray, iv);
    const QFETCH(QByteArray, startsWith);
    const QFETCH(QByteArray, endsWith);

    const QByteArray plainText = qossl::pkcs7Unpad( qossl::aesCbcDecrypt(data,key,iv) );

    QVERIFY(plainText.startsWith(startsWith));
    QVERIFY(plainText.endsWith(endsWith));
}

void TestSet2::testAesCbcEncrypt_data()
{
    QTest::addColumn<QByteArray>("data");
    QTest::addColumn<QByteArray>("key");
    QTest::addColumn<QByteArray>("iv");

    QTest::newRow("Simple")
        << QByteArray("xygxygyxgxygxygvxygxygyxgxygxygvxygxygyxgxygxygv")
        << QByteArray("YELLOW SUBMARINE")
        << QByteArray(qossl::AesBlockSize,(char)0);

    QTest::newRow("2")
        << QByteArray("blah blah blah blah blah blah blah")
        << QByteArray("YELLOW SUBMARINE")
        << QByteArray("1234567891234567");
}

void TestSet2::testAesCbcEncrypt()
{
    const QFETCH( QByteArray, data);
    const QFETCH( QByteArray, key);
    const QFETCH( QByteArray, iv);

    const QByteArray paddedPlain = qossl::pkcs7Pad(data, qossl::AesBlockSize);
    const QByteArray cipherText = qossl::aesCbcEncrypt(paddedPlain,key,iv);
    const QByteArray paddedPlain2 = qossl::aesCbcDecrypt(cipherText,key,iv);
    const QByteArray plain = qossl::pkcs7Unpad(paddedPlain2,qossl::AesBlockSize);

    // Decrypting should recover data.
    QCOMPARE(plain, data);
}
