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

namespace {
    double findBestXorChar(const QByteArray & cipherText, QByteArray & bestPlain, int & bestCipherChar) {
        double maxScore = 0;
        int cipherChar = -1;
        for (int i=0; i<256; ++i) {
            QByteArray xorcodeBin(1,static_cast<char>(i));
            const QByteArray testPlain = qossl::xorByteArray(cipherText,xorcodeBin);
            const double score = qossl::scoreEnglishText(testPlain);
            if (score > maxScore) {
                maxScore = score;
                bestPlain = testPlain;
                cipherChar = i;
            }
        }
        bestCipherChar = cipherChar;
        return maxScore;
    }
}
void TestSet1::testXorCrack()
{
    const QByteArray cipherText = QByteArray::fromHex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    QByteArray bestPlain;

    int cipherChar = -1;
    double maxScore = findBestXorChar(cipherText, bestPlain, cipherChar);

    qDebug() << maxScore << cipherChar << bestPlain;
    QCOMPARE(cipherChar, 88);
}


void TestSet1::testXorCrack2()
{
    QFile file(":/qossl_test_resources/rsc/set1/4.txt");
    QVERIFY(file.open(QIODevice::ReadOnly));

    QByteArray bestPlainOverall;
    double maxScoreOverall = 0;
    int line = 0;
    int bestLine = -1;
    while(true) {
        ++line;
        const QByteArray cipherTextHex = file.readLine();
        if (cipherTextHex.isEmpty()) {
            if (file.atEnd() || !file.isReadable()) {
                break;
            } else {
                continue;
            }
        }

        const QByteArray cipherText = QByteArray::fromHex(cipherTextHex.trimmed());

        QByteArray bestPlain;
        int cipherChar = -1;
        double score = findBestXorChar(cipherText, bestPlain, cipherChar);

        QVERIFY(score <= 1);

        if (score > maxScoreOverall) {
            maxScoreOverall= score;
            bestPlainOverall = bestPlain;
            bestLine = line;
                    qDebug() << line << score << cipherTextHex;
        }
    }

    file.close();

    qDebug() << maxScoreOverall << bestPlainOverall << bestLine;
}
