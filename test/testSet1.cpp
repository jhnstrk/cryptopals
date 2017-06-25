#include "testSet1.h"

#include <utils.h>

#include <QByteArray>
#include <QDebug>
#include "test.h"

JDS_ADD_TEST(TestSet1)

void TestSet1::initTestCase()
{

}

void TestSet1::cleanupTestCase()
{

}

void TestSet1::knownHexBase64_data()
{
    QTest::addColumn<QByteArray>("hex");
    QTest::addColumn<QByteArray>("base64");

    // Set 1 Challenge 1
    QTest::newRow("Challenge1")
        << QByteArray("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
        <<  QByteArray("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
}
void TestSet1::knownHexBase64()
{
    QFETCH( QByteArray, hex);
    QFETCH( QByteArray, base64);

    QByteArray binary = QByteArray::fromHex(hex);
    QByteArray actual = binary.toBase64();

    QCOMPARE(actual, base64);
}

void TestSet1::testXor_data()
{
    QTest::addColumn<QByteArray>("plain");
    QTest::addColumn<QByteArray>("xorcode");
    QTest::addColumn<QByteArray>("expected");

    // Set 1 Challenge 1
    QTest::newRow("Challenge1")
        << QByteArray("1c0111001f010100061a024b53535009181c")
        <<  QByteArray("686974207468652062756c6c277320657965")
         << QByteArray("746865206b696420646f6e277420706c6179");
}
void TestSet1::testXor()
{
    QFETCH( QByteArray, plain);
    QFETCH( QByteArray, xorcode);
    QFETCH( QByteArray, expected);

    const QByteArray binary = QByteArray::fromHex(plain);
    const QByteArray xorcodeBin = QByteArray::fromHex(xorcode);

    const QByteArray actual = qossl::xorByteArray(binary,xorcodeBin);

    QCOMPARE(actual.toHex(), expected);
}

