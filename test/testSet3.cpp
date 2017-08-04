#include "testSet3.h"

#include <utils.h>
#include <mersene_twister.h>


#include <QByteArray>
#include <QDateTime>
#include <QDebug>
#include "test.h"

#include <algorithm>

JDS_ADD_TEST(TestSet3)

void TestSet3::initTestCase()
{

}

void TestSet3::cleanupTestCase()
{

}


class Challenge17 {
public:

    Challenge17() : m_key(qossl::randomAesKey()) { }

    static QByteArray randomString()
    {
        using namespace qossl;
        QList<QByteArray> strings = QList<QByteArray>()
                << "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="
                <<  "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic="
                <<  "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw=="
                <<  "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg=="
                <<  "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl"
                <<  "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA=="
                <<  "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw=="
                <<  "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8="
                <<  "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g="
                <<  "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93";

        return strings.at(randomUChar() % strings.size() );
    }

    QByteArray firstFunc(QByteArray & iv) {

        QByteArray plain = QByteArray::fromBase64(randomString());

        iv = qossl::randomBytes(qossl::AesBlockSize);
        plain = qossl::pkcs7Pad(plain, qossl::AesBlockSize);

        return qossl::aesCbcEncrypt(plain,m_key,iv);
    }

    bool secondFunc(const QByteArray & cipherText, const QByteArray & iv){

        QByteArray plain = qossl::aesCbcDecrypt(cipherText,m_key, iv);

        try {
            plain = qossl::pkcs7Unpad(plain, qossl::AesBlockSize);
        }
        catch (qossl::PaddingException & e) {
            return false;
        }
        return true;
    }

private:
    QByteArray m_key,m_iv;
};

void TestSet3::testChallenge17()
{
    Challenge17 obj;

    QByteArray iv;
    const QByteArray e1 = obj.firstFunc(iv);

    QVERIFY(obj.secondFunc(e1,iv)); // no tampering, should be ok!

    QVERIFY(e1.size() % qossl::AesBlockSize  == 0);

    QByteArray plain;
    for (int ipos = 0; ipos < e1.size(); ipos += qossl::AesBlockSize) {

        const int eEnd = e1.size() - ipos;
        QByteArray guessedBlock;
        for (int j=0; j<qossl::AesBlockSize; ++j){
            QList<int> hits;
            for (int i=0; i<256; ++i) {
                QByteArray tampered = e1.mid(0,eEnd);
                QByteArray tampered_iv= iv;
                // Start of the block before.
                int n0 = tampered.size() - qossl::AesBlockSize - 1;
                if (n0 > 0) {
                    for (int k=0;k<j;++k) {
                        tampered.data()[n0 - k] ^= (guessedBlock.at(k) ^ (j+1));
                    }
                    tampered.data()[n0 - j] ^=  (i ^ (j+1));
                } else {
                    // Mess with the IV for first block.
                    n0 = qossl::AesBlockSize - 1;
                    for (int k=0;k<j;++k) {
                        tampered_iv.data()[n0 - k] ^= (guessedBlock.at(k) ^ (j+1));
                    }
                    tampered_iv.data()[n0 - j] ^=  (i ^ (j+1));
                }

                if (obj.secondFunc(tampered,tampered_iv)) {
                    hits << i;
                }

                if ( (hits.size() > 0) && (i > qossl::AesBlockSize) ) {
                    break;
                }
            }

            guessedBlock.append(hits.back());
        }

        plain.append(guessedBlock);
    }


    std::reverse(plain.begin(), plain.end());
    qDebug() << plain;
}

void TestSet3::testChallenge18_data()
{
    QTest::addColumn<QByteArray>("cipherText");
    QTest::addColumn<quint64>("nonce");
    QTest::addColumn<quint64>("counter");
    QTest::addColumn<QByteArray>("key");

    // Set 1 Challenge 1
    QTest::newRow("Challenge18")
        << QByteArray::fromBase64("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
        << quint64(0) << quint64(0)
        << QByteArray("YELLOW SUBMARINE");
}
void TestSet3::testChallenge18()
{
    const QFETCH( QByteArray, cipherText);
    const QFETCH( quint64, nonce);
    const QFETCH( quint64, counter);
    const QFETCH( QByteArray, key);

    const QByteArray actual = qossl::aesCtrDecrypt(cipherText, key, nonce, counter);
    qDebug() << actual; //"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "

    QCOMPARE(actual.size(), cipherText.size());

}

namespace {


    QByteArray extractNthByte(const QList<QByteArray> & input, const int ipos) {
        QByteArray ret;
        ret.reserve(input.size());
        foreach (const QByteArray & item, input) {
            if (ipos < item.size()) {
                ret.append(item.at(ipos));
            }
        }
        return ret;
    }

    unsigned char guessKeyByteAt(const QList<QByteArray> & cipherList, const int ipos)
    {
        const QByteArray nth = extractNthByte(cipherList, ipos);
        QByteArray temp;
        int iChar = 0;
        qossl::findBestXorChar(nth, temp, iChar);
        return iChar;
    }
}
void TestSet3::testChallenge19()
{
    const QList<QByteArray> plainb64List = QList<QByteArray>()
            << "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ=="
            << "Q29taW5nIHdpdGggdml2aWQgZmFjZXM="
            << "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ=="
            << "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4="
            << "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk"
            << "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA=="
            << "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ="
            << "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA=="
            << "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU="
            << "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl"
            << "VG8gcGxlYXNlIGEgY29tcGFuaW9u"
            << "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA=="
            << "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk="
            << "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg=="
            << "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo="
            << "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="
            << "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA=="
            << "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA=="
            << "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA=="
            << "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg=="
            << "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw=="
            << "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA=="
            << "U2hlIHJvZGUgdG8gaGFycmllcnM/"
            << "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w="
            << "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4="
            << "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ="
            << "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs="
            << "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA=="
            << "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA=="
            << "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4="
            << "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA=="
            << "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu"
            << "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc="
            << "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs"
            << "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs="
            << "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0"
            << "SW4gdGhlIGNhc3VhbCBjb21lZHk7"
            << "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw="
            << "VHJhbnNmb3JtZWQgdXR0ZXJseTo="
            << "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=";

    QList<QByteArray> cipherList;
    const QByteArray key = qossl::randomAesKey();
    const quint64 nonce = 0;
    const quint64 count0 = 0;
    foreach (const QByteArray & b64, plainb64List) {
        cipherList << qossl::aesCtrEncrypt(QByteArray::fromBase64(b64), key,nonce,count0);
    }

    const int len = qossl::maxLen(cipherList);

    QByteArray guessedKeyStream;
    guessedKeyStream.resize(len);
    for (int ipos = 0; ipos<len; ++ipos) {
        guessedKeyStream[ipos] = guessKeyByteAt(cipherList, ipos);
    }

    QList< QByteArray > plainTexts;
    foreach (const QByteArray & cipherText, cipherList) {
        plainTexts << qossl::xorByteArray(cipherText, guessedKeyStream);
        qDebug() << plainTexts.back();
    }

    // Results above are close, not perfect, especially near the end.
    // Also cannot resolve fist character as all upper case, and cannot differentiate with lower.
    QVERIFY(plainTexts.at(0).toLower().startsWith("i have met them at close of da"));
    QCOMPARE(plainTexts.at(1).toLower(), QByteArray("coming with vivid faces"));
}

namespace {
QList <QByteArray> readChallenge20()
{
    QFile file(":/qossl_test_resources/rsc/set3/20.txt");
    if (!file.open(QIODevice::ReadOnly)) {
        throw qossl::RuntimeException("Cannot open file");
    }

    QList <QByteArray> cipherTexts;

    while(true) {
        QByteArray next = file.readLine();
        if (next.isNull()) {
            break;
        }
        cipherTexts << QByteArray::fromBase64(next);
    }
    file.close();
    return cipherTexts;
}
}
void TestSet3::testChallenge20()
{
    const QList <QByteArray> cipherTexts = readChallenge20();
    QVERIFY(cipherTexts.size() > 1);

    const int minLen = qossl::minLen(cipherTexts);

    QVERIFY(minLen > 0);

    QByteArray concatMid;
    foreach (const QByteArray & item, cipherTexts) {
        concatMid.append(item.mid(0,minLen));
    }

    QByteArray derivedKey(minLen, '\0');

    double totalScore = 0;
    for (int k=0;k<minLen; ++k){
        const QByteArray subsampled = qossl::subsample(concatMid, k, minLen);
        QByteArray bestPlain;
        int cipherChar = 0;
        totalScore += qossl::findBestXorChar(subsampled, bestPlain, cipherChar);
        derivedKey[k] = static_cast<char>(cipherChar);
    }

    qDebug() << qossl::xorByteArray(concatMid, derivedKey);

}

void TestSet3::testChallenge21()
{
    qossl::MerseneTwister19937 twister(1);

    // Expected first 10 values when seeded with 1.
    QList<unsigned int> expected = QList<unsigned int>()
            << 1791095845
               << 4282876139
               << 3093770124
               << 4005303368
               << 491263
               << 550290313
               << 1298508491
               << 4290846341
               << 630311759
               << 1013994432;

    for (int i=0; i<10; ++i) {
        QCOMPARE(twister.extract_number(), expected.at(i));
    }
}

namespace {

    unsigned int findSeed( const unsigned int actual, const qint64 tnow )
    {
        qossl::MerseneTwister19937 twister;
        for (qint64 i=0; i<3600; ++i) {
            const unsigned int testseed = (unsigned int)(tnow - i);
            twister.seed(testseed);
            const unsigned int value = twister.extract_number();
            if (value == actual) {
                return testseed;
            }
        }
        return 0; // seed not found.
    }

}
void TestSet3::testChallenge22()
{
    using namespace qossl;

    MerseneTwister19937 twister;
    // secs since epoch.
    const qint64 t1 = QDateTime::currentDateTime().toMSecsSinceEpoch() / 1000;

    // simulate wait.
    const qint64 t2 = t1 + 40 + (randomUInt() % 1000);

    twister.seed(t2);
    const unsigned int value = twister.extract_number();

    // simulate wait.
    const qint64 t3 = t2 + 40 + (randomUInt() % 1000);

    // find seed by scanning all possible seeds in the recent past.
    const unsigned int guessedSeed = findSeed(value,t3);

    QCOMPARE(guessedSeed, t2);
}

void TestSet3::testUnTemper()
{
    const QList<unsigned int> samples = QList<unsigned int>()
            << 0 << 1 << (~(unsigned int)0) << 2 << 16
            << 0xf0f0f0f0 << 0x12345678;

    using namespace qossl;

    foreach (const unsigned int input, samples) {
        QCOMPARE( input, MerseneTwister19937::untemper(
                      MerseneTwister19937::temper(input)));
    }
}

void TestSet3::testChallenge23()
{
    using namespace qossl;

    MerseneTwister19937 twister;

    twister.seed( qossl::randomUInt() );

    QList<unsigned int> state;
    const int n = MerseneTwister19937::stateSize();
    state.reserve(n);

    for (int i=0; i<n; ++i) {
        state.append( MerseneTwister19937::untemper(twister.extract_number()) );
    }

    MerseneTwister19937 cloneTwister(state, n);

    for (int i=0; i<2*n; ++i) {
        QCOMPARE( twister.extract_number(), cloneTwister.extract_number() );
    }

    // The attack could be harder if
    // - the generator included hidden state information
    // - the generator used a hash before supplying the data.
    // If each output were hashed it would be impossible to reverse it => impossible to clone.
}


namespace {

// Encapsulate MT1997 to spit out one byte at a time.
class TwisterByteStream {
public:
    TwisterByteStream(unsigned int seed) :
        m_sample(0), m_byte(4),m_twister(seed)
    {}

    unsigned char sample() {
        if (m_byte >= 4) {
            m_sample = m_twister.extract_number();
            m_byte = 0;
        }
        const unsigned char ret = (m_sample >> m_byte ) & 0xFF;
        ++m_byte;
        return ret;
    }

private:
    unsigned int m_sample;
    unsigned int m_byte;
    qossl::MerseneTwister19937 m_twister;
};

// Encode and Decode are same operation.
QByteArray mt19937EncodeDecode(const QByteArray & plainText, unsigned int seed)
{
    QByteArray cipherText = plainText;
    unsigned char * p = reinterpret_cast<unsigned char*>(cipherText.data());

    TwisterByteStream twister(seed);

    for (int i = 0; i< plainText.size(); ++i ) {
        p[i] ^= (twister.sample() & 0xFF);
    }
    return cipherText;
}

// With a 16-bit seed, as specified.
QByteArray mt19937EncodeDecode_16(const QByteArray & plainText, quint16 seed)
{
    return mt19937EncodeDecode(plainText, seed);
}

} // anon

void TestSet3::testMt19937Cipher_data()
{
    QTest::addColumn<QByteArray>("plainText");
    QTest::addColumn<unsigned int>("key");

    QTest::newRow("Empty") << QByteArray() << (unsigned int) 1234;
    QTest::newRow("1") << QByteArray("1") << (unsigned int) 0;
    QTest::newRow("12") << QByteArray("12") << (unsigned int) 0;
    QTest::newRow("1234") << QByteArray("1234") << (unsigned int) 0xFFFFFFFF;
    QTest::newRow("asdf..") << QByteArray("asdfasdfsadfasdfasdfasdfasdfa") << (unsigned int) 0xFFFFFFFF;
    QTest::newRow("a..1500") << QByteArray(1500,'a') << (unsigned int) 123;
}

void TestSet3::testMt19937Cipher()
{
    const QFETCH( QByteArray, plainText);
    const QFETCH( unsigned int, key);

    const QByteArray cipherText = mt19937EncodeDecode(plainText, key);

    if (plainText.size() > 0) {
        QVERIFY(cipherText != plainText);
    }

    const QByteArray recoveredPlain = mt19937EncodeDecode(cipherText, key);

    QCOMPARE(recoveredPlain, plainText);
}

namespace {

quint16 recoverKey(const QByteArray & cipherText, const QByteArray & plain, bool & ok)
{

    const QByteArray encodedPlain = cipherText.right(plain.size());

    // xor to extract byte stream
    const QByteArray keyStreamBytes = qossl::xorByteArray(encodedPlain, plain);

    const int firstIx = cipherText.size() - plain.size();

    // Brute force.
    for (unsigned int i=0; i<0x10000; ++i) {
        TwisterByteStream keyStream(i);
        for (int j=0; j<firstIx; ++j) {
            keyStream.sample();    // Dump first N samples
        }
        bool found = true;
        for (int j=0; j<keyStreamBytes.size(); ++j) {
            if (keyStream.sample() != (unsigned char)keyStreamBytes.at(j)) {
                found = false;
                break;
            }
        }

        if (found) {
            ok = true;
            return (quint16)i;
        }
    }
    ok = false;
    return 0;
}

QByteArray makePasswordResetToken()
{
    TwisterByteStream stream(QDateTime::currentMSecsSinceEpoch() / 1000);
    QByteArray randomBytes;
    randomBytes.reserve(16);
    for (int i=0; i<16; ++i) {
        randomBytes.append((char)stream.sample());
    }
    return randomBytes;
}

bool isFromMtPRNGwithTime(const QByteArray & bytes, qint64 now = QDateTime::currentMSecsSinceEpoch() / 1000)
{
    TwisterByteStream stream(now);
    for (int i =0; i<bytes.size(); ++i) {
        if ((unsigned char)(bytes.at(i)) != stream.sample()) {
            return false;
        }
    }
    return true;
}
}


void TestSet3::testChallenge24()
{
    QByteArray known('A', 14);
    QByteArray plainText = qossl::randomBytes(qossl::randomUInt() % 1000) + known;

    const quint16 key = qossl::randomUInt() & 0xFFFF;

    const QByteArray cipherText = mt19937EncodeDecode_16(plainText, key);

    bool ok = false;
    const quint16 recoveredKey = recoverKey(cipherText, plainText, ok);

    QCOMPARE(recoveredKey, key);
    QVERIFY(ok);
    qDebug() << "Key" << recoveredKey;

    const QByteArray token = makePasswordResetToken();

    const qint64 now = QDateTime::currentMSecsSinceEpoch() / 1000;
    QVERIFY( isFromMtPRNGwithTime(token,now) || isFromMtPRNGwithTime(token, now -1));

    QVERIFY(!isFromMtPRNGwithTime(QByteArray('a',16)));
    QVERIFY(!isFromMtPRNGwithTime(token,now + 100));

}
