#include "testSet3.h"

#include <utils.h>

#include <QByteArray>
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

    int maxLen(const QList<QByteArray> & input) {
        int ret = 0;
        foreach (const QByteArray & item, input) {
            if (ret < item.size()) {
                ret = item.size();
            }
        }
        return ret;
    }
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
        double highscore = 0;
        unsigned char highchar = 0;
        for (int i=0; i<256; ++i) {
            QByteArray xored = qossl::xorByteArray(nth, QByteArray(16,(char)i));
            const double value = qossl::scoreEnglishText(xored);
            if (value > highscore) {
                highchar = i;
                highscore = value;
            }
        }
        return highchar;
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

    const int len = maxLen(cipherList);

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
