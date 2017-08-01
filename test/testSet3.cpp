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
