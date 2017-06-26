#include "testSet1.h"

#include <utils.h>

#include <QByteArray>
#include <QDebug>
#include "test.h"

#include <algorithm>

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

    // Set 1 Challenge 2
    QTest::newRow("Challenge2")
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
        }
    }

    file.close();

    qDebug() << maxScoreOverall << bestPlainOverall << bestLine;
    QCOMPARE(bestPlainOverall, QByteArray("Now that the party is jumping\n"));
}

void TestSet1::testRepeatingXor_data()
{
    QTest::addColumn<QByteArray>("plain");
    QTest::addColumn<QByteArray>("xorcode");
    QTest::addColumn<QByteArray>("expected");

    // Set 1 Challenge 5
    QTest::newRow("Challenge5")
        << QByteArray("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
        <<  QByteArray("ICE")
         << QByteArray("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
                       "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
}
void TestSet1::testRepeatingXor()
{
    QFETCH( QByteArray, plain);
    QFETCH( QByteArray, xorcode);
    QFETCH( QByteArray, expected);

    const QByteArray actual = qossl::xorByteArray(plain,xorcode);

    QCOMPARE(actual.toHex(), expected);
}

void TestSet1::testHammingDistance_data()
{
    QTest::addColumn<QByteArray>("lhs");
    QTest::addColumn<QByteArray>("rhs");
    QTest::addColumn<int>("expected");

    QTest::newRow("Sample")
        << QByteArray("this is a test")
        << QByteArray("wokka wokka!!!")
         << 37;

    QTest::newRow("Sample (L <--> R)")
        << QByteArray("wokka wokka!!!")
        << QByteArray("this is a test")
         << 37;

    QTest::newRow("Equal")
        << QByteArray("123456")
        << QByteArray("123456")
        << 0;

    QTest::newRow("Mismatch")
        << QByteArray::fromHex("0000000000000000")
        << QByteArray::fromHex("FFFFFFFFFFFFFFFF")
        << (16*4);
}

void TestSet1::testHammingDistance()
{
    const QFETCH( QByteArray, lhs);
    const QFETCH( QByteArray, rhs);
    const QFETCH( int, expected);

    const int actual = qossl::hammingDistance(lhs,rhs);
    QCOMPARE( actual, expected);
}


namespace {
    struct KeyScore {
        KeyScore( double s, int size) :
            score(s), keySize(size)
        {}

        double score;
        int keySize;
    };

    bool lessThanKeyScore( const KeyScore & lhs, const KeyScore & rhs) {
        return lhs.score < rhs.score;
    }
}

void TestSet1::testBreakRepeatingXor()
{
    QFile file(":/qossl_test_resources/rsc/set1/6.txt");
    QVERIFY(file.open(QIODevice::ReadOnly));
    const QByteArray cipherText = QByteArray::fromBase64(file.readAll());
    file.close();
    QVERIFY(!cipherText.isEmpty());
    
    QList <KeyScore> keyResults;

    const int keySizeMax = 40;
    for (int keySize = 2; keySize < keySizeMax; ++keySize) {
        double scoreTotal = 0;
        int nblock = cipherText.size() / (2*keySize);

        for (int iblock = 0; iblock < nblock; ++iblock) {
            const QByteArray b1 = cipherText.mid(2*iblock*keySize,keySize);   // First block
            const QByteArray b2 = cipherText.mid(2*iblock*keySize + keySize, keySize); // second block

            scoreTotal += qossl::hammingDistance(b1,b2);
        }

        // Normalized score
        const double score = scoreTotal /
                (static_cast<double>(keySize) * nblock);
        keyResults.push_back(KeyScore(score, keySize));
    }

    std::stable_sort(keyResults.begin(), keyResults.end(), lessThanKeyScore);

    QByteArray recoveredKey;

    for (int i=0; i<1; ++i) {
        const KeyScore & item(keyResults.at(i));
        qDebug() << i << item.keySize << item.score;

        const int keySize = item.keySize;
        QByteArray derivedKey(keySize, '\0');

        double totalScore = 0;
        for (int k=0;k<keySize; ++k){
            const QByteArray subsampled = qossl::subsample(cipherText, k, keySize);
            QByteArray bestPlain;
            int cipherChar = 0;
            totalScore += findBestXorChar(subsampled, bestPlain, cipherChar);
            derivedKey[k] = static_cast<char>(cipherChar);
        }

        //qDebug() << derivedKey << totalScore / keySize;

        if (i==0) {
            QByteArray recoveredPlainText = qossl::xorByteArray(cipherText,derivedKey);
            //qDebug() << recoveredPlainText;
            recoveredKey = derivedKey;
        }
    }

    QCOMPARE(recoveredKey, QByteArray("Terminator X: Bring the noise"));

}

void TestSet1::testAesEcb()
{
    QFile file(":/qossl_test_resources/rsc/set1/7.txt");
    QVERIFY(file.open(QIODevice::ReadOnly));
    const QByteArray cipherText = QByteArray::fromBase64(file.readAll());
    file.close();
    QVERIFY(!cipherText.isEmpty());

    const QByteArray key("YELLOW SUBMARINE");

    QByteArray plain = qossl::aesEcbDecrypt(cipherText, key);

    QVERIFY(plain.startsWith("I'm back and I'm ringin' the bell \nA rockin' on"));
    QVERIFY(plain.endsWith("Play that funky music \n\x04\x04\x04\x04"));
}

void TestSet1::testDetectAesEcb()
{
    const int AesBlockSize = 16;
    QFile file(":/qossl_test_resources/rsc/set1/8.txt");
    QVERIFY(file.open(QIODevice::ReadOnly));
    int iLine = 0;

    int bestdupCount = 0;
    int bestLine = -1;
    QByteArray bestCipher;

    while(file.isReadable() && !file.atEnd()) {
        ++iLine;
        // Read a sample
        const QByteArray cipherText = QByteArray::fromHex(file.readLine());

        if (cipherText.isEmpty()) {
            QVERIFY(iLine > 1);
            break;
        }
        QHash<QByteArray, int> histo;

        // Break into 16 byte chunks and make a histogram.
        for (int i=0; i<cipherText.size() - AesBlockSize + 1; i+=AesBlockSize) {
            const QByteArray chunk = cipherText.mid(i,AesBlockSize);
            histo[chunk]++;
        }

        // If many of the blocks appear more than once, that's suspicious.
        const int dupCount = (cipherText.size() / AesBlockSize) - histo.size();
        if (dupCount > bestdupCount) {
            bestdupCount = dupCount;
            bestLine = iLine;
            bestCipher = cipherText;
        }
    }

    file.close();

    QCOMPARE(bestLine, 133);
    QVERIFY(bestCipher.toHex().startsWith("d880619740a8a19b7840a8a31c810a3d"));
}
