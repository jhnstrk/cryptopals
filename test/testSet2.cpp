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

class EncryptionOracleC11 : public qossl::EncryptionOracle {
public:
    EncryptionOracleC11(): m_method(qossl::Aes::None)
    {}
    virtual ~EncryptionOracleC11() {}

    QByteArray encrypt(const QByteArray & input) Q_DECL_OVERRIDE {
        using namespace qossl;

        m_key = randomAesKey();
        m_method = (randomUChar() & 1) ? Aes::CBC : Aes::ECB;

        const int lPad = (randomUChar() % 5) + 5;
        const int rPad = (randomUChar() % 5) + 5;

        // Start and end padding
        QByteArray padPlain = randomBytes(lPad) + input + randomBytes(rPad);

        padPlain = pkcs7Pad(padPlain, AesBlockSize);

        QByteArray ret;

        switch( this->m_method ) {
        case Aes::CBC:
            m_iv = randomBytes(AesBlockSize);
            ret = aesCbcEncrypt(padPlain, m_key, m_iv);
            break;
        case Aes::ECB:
            ret = aesEcbEncrypt(padPlain,m_key);
            break;
        default:
            qWarning() << "Invalid method";
            ret = padPlain;
            break;
        }

        return ret;
    }

    qossl::Aes::Method getMethod() const { return m_method; }
    QByteArray getKey() const { return m_key; }
    QByteArray getIv() const  { return m_iv; }
private:
    qossl::Aes::Method m_method;  // CBC / ECB
    QByteArray m_key, m_iv;
};

void TestSet2::testEncryptionOracle_data()
{
    QTest::addColumn<QByteArray>("data");

    QTest::newRow("1") << QByteArray("xygxygyxgxygxygvxygxygyxgxygxygvxygxygyxgxygxygv").repeated(20);
    QTest::newRow("2") << QByteArray("blah blah blah blah blah blah blah").repeated(20);
}

void TestSet2::testEncryptionOracle()
{
    const QFETCH( QByteArray, data);

    for (int i=0;i<3;++i) {
        using namespace qossl;
        EncryptionOracleC11 oracle;
        const QByteArray enc = oracle.encrypt(data);
        QByteArray plain;
        if (oracle.getMethod() == Aes::CBC) {
            plain = aesCbcDecrypt(enc, oracle.getKey(), oracle.getIv());
        } else if (oracle.getMethod() == Aes::ECB) {
            plain = aesEcbDecrypt(enc,oracle.getKey());
        } else {
            QFAIL("Bad enc");
        }
        QVERIFY(plain.contains(data));

        QCOMPARE(estimateAesMethod(enc), oracle.getMethod());

        qDebug() << oracle.getMethod();
    }
}

class EncryptionOracleC12 : public qossl::EncryptionOracle {
public:
    EncryptionOracleC12(): m_method(qossl::Aes::None)
    {}
    virtual ~EncryptionOracleC12() {}

    QByteArray encrypt(const QByteArray & input) Q_DECL_OVERRIDE;

    qossl::Aes::Method getMethod() const { return m_method; }
    QByteArray getKey() const { return m_key; }
    void setKey(const QByteArray & key) { m_key = key; }
    QByteArray getIv() const { return m_iv; }
private:
    qossl::Aes::Method m_method;  // CBC / ECB
    QByteArray m_key, m_iv;
};

QByteArray EncryptionOracleC12::encrypt(const QByteArray & input)
{
    if (m_key.isEmpty()) {
        m_key = qossl::randomAesKey();
    }

    m_iv = randomBytes(qossl::AesBlockSize);
    m_method = qossl::Aes::ECB;

    const QByteArray fixedPad = QByteArray::fromBase64(
                "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                "YnkK");

    // Start and end padding
    QByteArray padPlain = input + fixedPad;

    padPlain = pkcs7Pad(padPlain, qossl::AesBlockSize);

    QByteArray ret = qossl::aesEcbEncrypt(padPlain,m_key);

    return ret;
}



void TestSet2::testBreakEncrypionOracle2()
{
    using namespace qossl;
    EncryptionOracleC12 oracle;
    oracle.setKey(randomAesKey());

    const int blockSize = detectBlockSize(oracle);
    QCOMPARE(blockSize, (int)AesBlockSize);

    {
        const QByteArray sample = QByteArray(2*blockSize,'a');
        QByteArray encSample = oracle.encrypt(sample);

        // This confirms ECB... first 2 blocks are same.
        QVERIFY(encSample.mid(0,blockSize) == encSample.mid(blockSize,blockSize));
    }
    QByteArray plain;
    for (int ipos = 0; ipos < blockSize; ++ipos) {

        // Build dictionary.
        QHash< QByteArray, char > encBlocks;
        for (int i=0;i<256; ++i) {
            const QByteArray sample = QByteArray(blockSize - 1 - ipos,'A').append(plain).append((char)i);
            const QByteArray eblock = oracle.encrypt(sample).left(blockSize);
            encBlocks[ eblock ] = (char)i;
        }

        // Get actual encrypted block.
        const QByteArray paddedPlain = QByteArray(blockSize - 1 - ipos,'A');
        const QByteArray ref1 = oracle.encrypt(paddedPlain).left(blockSize);
        plain.append(encBlocks.value(ref1));
    }

    qDebug() << "First block is " << plain;
    QCOMPARE( plain, QByteArray("Rollin' in my 5."));

}

void TestSet2::testChallenge13()
{
    using namespace qossl;
    const QString kvlist = "foo=bar&baz=qux&zap=zazzle";
    QHash<QString,QString> value = qossl::keyValueParse(kvlist);
    QCOMPARE(value.value("foo"), QString("bar"));
    QCOMPARE(value.value("baz"), QString("qux"));
    QCOMPARE(value.value("zap"), QString("zazzle"));

    QCOMPARE(profile_for("foo@bar.com"), QString("email=foo@bar.com&uid=10&role=user"));

    const QByteArray key = randomAesKey();

    //Method:
    // Use long blocks 'AAAAAAAAAx@mail.com' as the email address
    // Final text must be block aligned.
}
