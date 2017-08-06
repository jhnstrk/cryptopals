#include "testSet4.h"

#include <utils.h>
#include "sha_1.h"

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


class Challenge27 {
public:
    Challenge27() : m_key(qossl::randomAesKey())
    {
        m_iv = m_key;  // Repurpose key as IV (bad).
    }

    // First func
    QByteArray encode(const QByteArray & userdata) const {

        QByteArray d1 = userdata;
        d1 = d1.replace('%', "%25");
        d1 = d1.replace(';', "%3B");
        d1 = d1.replace('=', "%3D");
        d1 = QByteArray("comment1=cooking%20MCs;userdata=")
             + d1
             + QByteArray(";comment2=%20like%20a%20pound%20of%20bacon");

        if (!this->isAscii(d1)) {
            throw qossl::RuntimeException("Bad plaintext:" + d1);
        }
        d1 = qossl::pkcs7Pad(d1,qossl::AesBlockSize);

        d1 = qossl::aesCbcEncrypt(d1,m_key,m_iv);
        return d1;
    }

    bool isAdmin(const QByteArray & encrypted) const {
        QByteArray dec = qossl::aesCbcDecrypt(encrypted, m_key, m_iv);

        if (!this->isAscii(dec)) {
            throw qossl::RuntimeException("Bad plaintext:" + dec);
        }

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

    static bool isAscii(const QByteArray & data)
    {
        if (data.isEmpty()) {
            return true;
        }

        foreach (const char c, data) {
            if ((c & 0x80) != 0) {
                return false;
            }
        }

        return true;
    }

    bool isKey(const QByteArray & key) const
    {
        return key == m_key;
    }
private:
    QByteArray m_key, m_iv;
};

void TestSet4::testChallenge27()
{
    const QByteArray userdata = "JUMPIN JACK FLAS";

    Challenge27 obj;
    const QByteArray regular = obj.encode(userdata);
    QVERIFY(!obj.isAdmin(regular));

    const QByteArray block1 = regular.mid(0,qossl::AesBlockSize);
    const QByteArray block3 = regular.mid(2*qossl::AesBlockSize,qossl::AesBlockSize);

    // C_1 + 0 + C_1
    const QByteArray tampered = block1 + QByteArray(qossl::AesBlockSize,'\0') + block1;

    // Attempt decryption, which is almost certain to throw an error.
    QByteArray message;
    try {
        obj.isAdmin(tampered);
    }
    catch (qossl::RuntimeException & e) {
        qDebug() << "Caught Exception" << e.whatBytes();
        message = e.whatBytes();
    }

    // Remove error string, leave plain text
    const int prefixLen = message.indexOf(':') + 1;
    QVERIFY(prefixLen >= 0);
    message = message.mid(prefixLen);

    // Extract blocks and recover key.
    const QByteArray pdash_1 = message.mid(0,qossl::AesBlockSize);
    const QByteArray pdash_3 = message.mid(2*qossl::AesBlockSize,qossl::AesBlockSize);
    const QByteArray key = qossl::xorByteArray(pdash_1, pdash_3);

    // Check key validity.
    QVERIFY(obj.isKey(key));
}

void TestSet4::testSha1_data()
{
    QTest::addColumn<QByteArray>("text");
    QTest::addColumn<QByteArray>("hash");

    QTest::newRow("Empty") << QByteArray() << QByteArray::fromHex("da39a3ee5e6b4b0d3255bfef95601890afd80709");
    QTest::newRow("A") << QByteArray("A") << QByteArray::fromHex("6dcd4ce23d88e2ee9568ba546c007c63d9131c1b");
    QTest::newRow("Fox1") << QByteArray("The quick brown fox jumps over the lazy dog")
                          << QByteArray::fromHex("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
    QTest::newRow("Fox2") << QByteArray("The quick brown fox jumps over the lazy cog")
                          << QByteArray::fromHex("de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3");
    QTest::newRow("Longer") << QByteArray("asdfasdfasdfasdfasdfasdfasdfasdfsadfasd"
             "fasdfasdfasdfasdflkjhlkhjopuyooiuh;wqjerkjqnrlkjbqwerqwrsadfavds")
                           << QByteArray::fromHex("746787344a16e144b4ce5547327b26d5c46f478d");

}

void TestSet4::testSha1()
{
    const QFETCH( QByteArray, text);
    const QFETCH( QByteArray, hash);

    const QByteArray actual = qossl::Sha1::hash(text);

    QCOMPARE(actual.toHex(), hash.toHex());
}


namespace {

class Sha1Mac {
public:
    Sha1Mac(const QByteArray & key) : m_key(key) {}
    ~Sha1Mac() {}

    QByteArray mac(const QByteArray & message) const {
        qossl::Sha1 hasher;
        hasher.addData(m_key);
        hasher.addData(message);
        return hasher.finalize();
    }

    bool isValid(const QByteArray & testmac, const QByteArray & message) const
    {
        return this->mac(message) == testmac;
    }

private:
    QByteArray m_key;
};
}

void TestSet4::testChallenge28()
{
    Sha1Mac maccer("MySecret");

    const QByteArray message = "The quick brown fox jumps over the lazy dog";

    const QByteArray mac = maccer.mac(message);

    // Correct mac validates the message.
    QVERIFY(maccer.isValid(mac,message));

    // Wrong message: Not valid.
    const QByteArray tamperMessage = "The slow brown fox jumps over the lazy dog";
    QVERIFY(!maccer.isValid(mac,tamperMessage));

    // Wrong key:: Not valid.
    Sha1Mac badmaccer("BadGuess");
    QVERIFY(!badmaccer.isValid(mac,message));
}
