#include "testSet4.h"

#include <utils.h>

#include <QByteArray>
#include <QDebug>
#include "test.h"

JDS_ADD_TEST(TestSet4)

void TestSet4::initTestCase()
{

}

void TestSet4::cleanupTestCase()
{

}

namespace {

}
void TestSet4::testCtrEdit()
{
    const quint64 nonce = qossl::randomUInt64();
    const QByteArray key = qossl::randomAesKey();

    //                            0123456789abcdef0123456789abcdef
    const QByteArray plainText = "This was the year that was";

    QByteArray cipherText = qossl::aesCtrEncrypt(plainText,key,nonce,0);
    qossl::aesCtrEdit(cipherText, key, nonce, 0xd, QByteArray("week"));

    const QByteArray plain2 = qossl::aesCtrDecrypt(cipherText,key,nonce,0);
    QCOMPARE(plain2, QByteArray("This was the week that was"));
}

void TestSet4::testChallenge25()
{
    QFile file(":/qossl_test_resources/rsc/set4/25.txt");
    QVERIFY(file.open(QIODevice::ReadOnly));
    const QByteArray data = QByteArray::fromBase64(file.readAll());
    file.close();
    const QByteArray ecbKey = ("YELLOW SUBMARINE");
    const QByteArray plainText = qossl::pkcs7Unpad( qossl::aesEcbDecrypt(data, ecbKey) );

    const quint64 nonce = qossl::randomUInt64();
    const QByteArray key = qossl::randomAesKey();
    const QByteArray cipherText = qossl::aesCtrEncrypt(plainText,key,nonce,0);


    QByteArray editCipherText = cipherText;
    const QByteArray hackerPlain = QByteArray(cipherText.size(),'\0');
    qossl::aesCtrEdit(editCipherText,key,nonce,0,hackerPlain);

    const QByteArray mask = qossl::xorByteArray(editCipherText, hackerPlain);
    const QByteArray recovered = qossl::xorByteArray(cipherText,mask);

    QVERIFY(recovered.startsWith("I'm back and I'm ringin' the bell \nA rockin' on"));
    QVERIFY(recovered.endsWith("Play that funky music \n"));
}

class Challenge26 {
public:
    Challenge26() : m_key(qossl::randomAesKey()),
        m_nonce(qossl::randomUInt64())
    {}

    // First func
    QByteArray encode(const QByteArray & userdata) const {
        QByteArray d1 = userdata;
        d1 = d1.replace('%', "%25");
        d1 = d1.replace(';', "%3B");
        d1 = d1.replace('=', "%3D");
        d1 = QByteArray("comment1=cooking%20MCs;userdata=")
             + d1
             + QByteArray(";comment2=%20like%20a%20pound%20of%20bacon");

        d1 = qossl::pkcs7Pad(d1,qossl::AesBlockSize);

        d1 = qossl::aesCtrEncrypt(d1,m_key,m_nonce,0);
        return d1;
    }

    bool isAdmin(const QByteArray & encrypted) const {
        QByteArray dec = qossl::aesCtrDecrypt(encrypted, m_key, m_nonce,0);
        dec = qossl::pkcs7Unpad(dec);

        QList<QByteArray> split = dec.split(';');
        foreach (const QByteArray & item, split) {
            const int ix = item.indexOf('=');
            if (ix == -1) {
                continue;
            }
            QByteArray key = item.mid(0,ix);
            QByteArray value = item.mid(ix + 1);
            if (key == "admin") {
                return value == "true";
            }
        }
        return false;
    }

private:
    QByteArray m_key;
    quint64 m_nonce;
};

void TestSet4::testChallenge26()
{
    Challenge26 obj;

    QByteArray trashblock = QByteArray(qossl::AesBlockSize, 'A'); // Anything.
    //                        0123456789abcdef
    QByteArray targetblock = "AadminBtrue";

    const QByteArray regular = obj.encode(trashblock + targetblock);
    QVERIFY(!obj.isAdmin(regular));

    // These are the bits we need to flip...
    // Turn ; into A, and = into B so they don't get escaped out.
    const char flipSemiColon = ((unsigned int)';') ^ ((unsigned int)'A');
    const char flipEquals = ((unsigned int)'=') ^ ((unsigned int)'B');

    // tamper with the block (unlike CBC we don't flip bits in the block before).
    QByteArray tampered = regular;
    const int n = 3 * qossl::AesBlockSize;
    tampered.data()[n + 0] ^= flipSemiColon;
    tampered.data()[n + 6] ^= flipEquals;

    // Confirm we now have an admin token.
    QVERIFY(obj.isAdmin(tampered));
}

