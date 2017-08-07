#include "testSet4.h"

#include <utils.h>
#include "sha_1.h"
#include "md4.h"
#include "bitsnbytes.h"
#include "hmac.h"

#include <QByteArray>
#include <QDebug>
#include <QElapsedTimer>
#include <QThread>

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
    QCOMPARE(actual.size(), (int)qossl::Sha1::HashSizeBytes);
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

namespace {
QByteArray computeSha1Padding(int messageLenBytes) {

    const int BlockSizeBytes = qossl::Sha1::BlockSizeBytes;
    const int remaining = (messageLenBytes + 1) % BlockSizeBytes;

    QByteArray ret;
    ret.append((char)0x80);
    if (remaining <= (BlockSizeBytes - 8) ) {
        ret.append( QByteArray((BlockSizeBytes - 8) - remaining,'\0'));
    } else {
        ret.append(QByteArray(BlockSizeBytes - remaining,'\0'));
        ret.append(QByteArray((BlockSizeBytes - 8),'\0'));
    }

    // Message length in bits
    ret.append( qossl::uint64Be(quint64(messageLenBytes) * CHAR_BIT) );

    return ret;
}

void splitHash(const QByteArray & hash, quint32 & a, quint32 & b, quint32 & c, quint32 & d, quint32 & e)
{
    if (hash.size() != 20) {
        throw qossl::RuntimeException("Bad hash size" + QByteArray::number(hash.size()));
    }
    
    using namespace qossl;
    const unsigned char * p = reinterpret_cast<const unsigned char *>(hash.constData());
    a = uint32_from_be(p);
    b = uint32_from_be(p+4);
    c = uint32_from_be(p+8);
    d = uint32_from_be(p+12);
    e = uint32_from_be(p+16);
    return;
}
}


void TestSet4::testChallenge29_1()
{
    //1. Check it works when I know the secret.
    const QByteArray theSecret = "MySecret";
    Sha1Mac maccer(theSecret);
    const QByteArray message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
    const QByteArray mac = maccer.mac(message);

    quint32 a,b,c,d,e;
    splitHash(mac,a,b,c,d,e);
    
    const QByteArray gluePadding = computeSha1Padding(theSecret.length() + message.length());
    const quint64 count0 = theSecret.length() + message.length() + gluePadding.length();

    const QByteArray tamperData = ";admin=1";

    qossl::Sha1 extendSha1(a,b,c,d,e,count0);
    extendSha1.addData(tamperData);
    const QByteArray tamperMac = extendSha1.finalize();

    const QByteArray tamperMessage = message + gluePadding + tamperData;
    QVERIFY(maccer.isValid(tamperMac, tamperMessage));
}

void TestSet4::testChallenge29_2()
{
    //2. With a random, unknown key
    const QByteArray theSecret = qossl::randomBytes(6 + (qossl::randomUChar() % 20)).toBase64();
    Sha1Mac maccer(theSecret);
    const QByteArray message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
    const QByteArray mac = maccer.mac(message);

    quint32 a,b,c,d,e;
    splitHash(mac,a,b,c,d,e);

    QByteArray tamperMac, tamperMessage;

    // Iterate over the key length until we find the right one.
    for (int guessLen = 0; guessLen < 50; ++guessLen) {
        const QByteArray gluePadding = computeSha1Padding(guessLen + message.length());
        const quint64 count0 = guessLen + message.length() + gluePadding.length();

        const QByteArray tamperData = ";admin=1";

        qossl::Sha1 extendSha1(a,b,c,d,e,count0);
        extendSha1.addData(tamperData);
        tamperMac = extendSha1.finalize();

        tamperMessage = message + gluePadding + tamperData;
        if (maccer.isValid(tamperMac, tamperMessage)) {
            qDebug() << "Secret length is" << guessLen;
            break;
        }
    }
    QVERIFY(maccer.isValid(tamperMac, tamperMessage));
    qDebug() << "Tampered mac:" << tamperMac.toBase64()
             << "Tampered message: " << tamperMessage;
}

void TestSet4::testMd4_data()
{
    QTest::addColumn<QByteArray>("text");
    QTest::addColumn<QByteArray>("hash");

    // From https://tools.ietf.org/html/rfc1320
    QTest::newRow("Empty") << QByteArray() << QByteArray::fromHex("31d6cfe0d16ae931b73c59d7e0c089c0");
    QTest::newRow("a") << QByteArray("a") << QByteArray::fromHex("bde52cb31de33e46245e05fbdbd6fb24");
    QTest::newRow("abc") << QByteArray("abc") << QByteArray::fromHex("a448017aaf21d8525fc10ae87aa6729d");
    QTest::newRow("message digest") << QByteArray("message digest") << QByteArray::fromHex("d9130a8164549fe818874806e1c7014b");
    QTest::newRow("abc..z") << QByteArray("abcdefghijklmnopqrstuvwxyz") << QByteArray::fromHex("d79e1c308aa5bbcdeea8ed63df412da9");
    QTest::newRow("a-zA-Z0-9") << QByteArray("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") << QByteArray::fromHex("043f8582f241db351ce627e153e7f0e4");
    QTest::newRow("123....") << QByteArray("12345678901234567890123456789012345678901234567890123456789012345678901234567890") << QByteArray::fromHex("e33b4ddc9c38f2199c3e7b164fcc0536");
}

void TestSet4::testMd4()
{
const QFETCH( QByteArray, text);
const QFETCH( QByteArray, hash);

const QByteArray actual = qossl::Md4::hash(text);

QCOMPARE(actual.toHex(), hash.toHex());
QCOMPARE(actual.size(), (int)qossl::Md4::HashSizeBytes);
}

// ----------------------------------------------------------------------------
// MD4
namespace {

class Md4Mac {
public:
    Md4Mac(const QByteArray & key) : m_key(key) {}
    ~Md4Mac() {}

    QByteArray mac(const QByteArray & message) const {
        qossl::Md4 hasher;
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

QByteArray computeMd4Padding(int messageLenBytes) {

    const int BlockSizeBytes = qossl::Md4::BlockSizeBytes;
    const int remaining = (messageLenBytes + 1) % BlockSizeBytes;

    QByteArray ret;
    ret.append((char)0x80);
    if (remaining <= (BlockSizeBytes - 8) ) {
        ret.append( QByteArray((BlockSizeBytes - 8) - remaining,'\0'));
    } else {
        ret.append(QByteArray(BlockSizeBytes - remaining,'\0'));
        ret.append(QByteArray((BlockSizeBytes - 8),'\0'));
    }

    // Message length in bits
    ret.append( qossl::uint64Le(quint64(messageLenBytes) * CHAR_BIT) );

    return ret;
}

void splitMd4Hash(const QByteArray & hash, quint32 & a, quint32 & b, quint32 & c, quint32 & d)
{
    if (hash.size() != 16) {
        throw qossl::RuntimeException("Bad hash size" + QByteArray::number(hash.size()));
    }

    using namespace qossl;
    const unsigned char * p = reinterpret_cast<const unsigned char *>(hash.constData());
    a = uint32_from_le(p);
    b = uint32_from_le(p+4);
    c = uint32_from_le(p+8);
    d = uint32_from_le(p+12);
    return;
}
}

void TestSet4::testChallenge30()
{
    const QByteArray theSecret = qossl::randomBytes(6 + (qossl::randomUChar() % 20)).toBase64();
    Md4Mac maccer(theSecret);
    const QByteArray message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
    const QByteArray mac = maccer.mac(message);

    quint32 a,b,c,d;
    splitMd4Hash(mac,a,b,c,d);

    QByteArray tamperMac, tamperMessage;

    // Iterate over the key length until we find the right one.
    for (int guessLen = 0; guessLen < 50; ++guessLen) {
        const QByteArray gluePadding = computeMd4Padding(guessLen + message.length());
        const quint64 count0 = guessLen + message.length() + gluePadding.length();

        const QByteArray tamperData = ";admin=1";

        qossl::Md4 extendMd4(a,b,c,d,count0);
        extendMd4.addData(tamperData);
        tamperMac = extendMd4.finalize();

        tamperMessage = message + gluePadding + tamperData;
        if (maccer.isValid(tamperMac, tamperMessage)) {
            qDebug() << "Secret length is" << guessLen;
            break;
        }
    }
    QVERIFY(maccer.isValid(tamperMac, tamperMessage));
    qDebug() << "Tampered mac:" << tamperMac.toBase64()
             << "Tampered message: " << tamperMessage;
}

void TestSet4::testHmacSha1_data()
{
    QTest::addColumn<QByteArray>("key");
    QTest::addColumn<QByteArray>("data");
    QTest::addColumn<QByteArray>("hash");

    // From Wikipedia
    QTest::newRow("Empty") << QByteArray() << QByteArray() << QByteArray::fromHex("fbdb1d1b18aa6c08324b7d64b71fb76370690e1d");
    QTest::newRow("key,fox")
            << QByteArray("key")
            << QByteArray("The quick brown fox jumps over the lazy dog")
            << QByteArray::fromHex("de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9");
}

void TestSet4::testHmacSha1()
{
    const QFETCH( QByteArray, key);
    const QFETCH( QByteArray, data);
    const QFETCH( QByteArray, hash);

    const QByteArray actual = qossl::hmacSha1(key,data);

    QCOMPARE(actual.toHex(), hash.toHex());
}


namespace {

    class FakeServer {
    public:
        FakeServer() : m_key(qossl::randomBytes(16).toBase64()), m_sleep(5) {}

        int request(const QByteArray & file, const QByteArray & signature) const {
            const QByteArray expected = this->expectedSig(file);
            if (!insecure_compare(signature, expected)) {
                return 500; // invalid MAC.
            }
            return 200; // OK
        }

        QByteArray expectedSig(const QByteArray & file) const {
            return qossl::hmacSha1(m_key, file);
        }
    private:
        bool insecure_compare(const QByteArray & left, const QByteArray & right) const
        {
            if (left.length() != right.length()) {
                return false;
            }

            const int len = left.length();
            for (int i=0; i<len; ++i) {
                if (left.at(i) != right.at(i)) {
                    return false;
                }
                QThread::msleep(m_sleep);
            }
            return true;
        }

    private:
        QByteArray m_key;
        const unsigned long m_sleep;
    };


    // Hacker side:

    class HmacAttack {
    public:
        HmacAttack( const FakeServer & server, const QByteArray & file ) :
            m_server(server), m_file(file) {}

        QByteArray deduceValidMac()
        {
            QByteArray mac;

            QVector<qint64> guessTimes;
            guessTimes.resize(m_signatureSize);

            for (int i=0; i<m_signatureSize; ++i) {
                QElapsedTimer timer;
                timer.start();
                mac += attackChar(mac);
                const qint64 eTime = timer.nsecsElapsed();
                qDebug() << mac.toHex() << "etime" << eTime;
                guessTimes[i] = eTime;
                const quint64 thresh = 2LL * 255LL * 1000000LL;  // 2ms, 255 attempts.
                if (i == 0) {
                    //
                } else if ( (eTime - (thresh)) <  guessTimes.at(i-1)) {
                    qDebug() << "Re re wind.";
                    mac = mac.left(i - 2);
                    i -= 3;
                    if (i < 0) i = -1;
                }
            }
            return mac;
        }

        char attackChar(const QByteArray & prefix)
        {
            const int at=prefix.length();
            if (at > m_signatureSize) {
                return 0;
            }

            QByteArray test( prefix +
                             QByteArray(m_signatureSize - prefix.length(),'\0') );

            char * pdata = test.data();
            qint64 maxtime = 0;
            int best = 0;

            for (int c=0; c<256; ++c) {
                pdata[at] = static_cast<char>(c);
                m_timer.restart();
                m_server.request(m_file,test);
                const qint64 elapsed = m_timer.nsecsElapsed();
                if (c == 0) {
                    maxtime = elapsed;
                } else if(maxtime < elapsed) {
                    maxtime = elapsed;
                    best = c;
                }
            }
            return static_cast<char>(best);
        }

    private:
        const FakeServer & m_server;
        const QByteArray & m_file;
        QElapsedTimer m_timer;
        static const int m_signatureSize = qossl::Sha1::HashSizeBytes;
    };


}
void TestSet4::testChallenge31()
{
    FakeServer theServer;

    const QByteArray testFile = "/etc/passwd";
    HmacAttack attacker(theServer, testFile);

    qDebug() << theServer.expectedSig(testFile).toHex();

    QByteArray attackSig = attacker.deduceValidMac();

    QCOMPARE( theServer.request(testFile, attackSig), 200);

    qDebug() << "Signature:" << attackSig;
}
