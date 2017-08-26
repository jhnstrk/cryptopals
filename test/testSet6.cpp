#include "testSet6.h"

#include <rsa.h>

#include <QByteArray>
#include <QCryptographicHash>
#include <QDebug>
#include <QSet>

#include <QTest>

#include "test.h"

JDS_ADD_TEST(TestSet6)


namespace {
    QByteArray sha1Hash(const QByteArray & data) {
        return QCryptographicHash::hash(data, QCryptographicHash::Sha1);
    }

    // The hypothetical server from Challenge 41
    class Server {
    public:
        Server() {
            Rsa::KeyPair keys = Rsa::rsaKeyGen(1024);
            m_privKey = keys.second;
            m_pubKey = keys.first;
        }

        QByteArray request(const QByteArray & cipherText) {
            const QByteArray hash = sha1Hash(cipherText);
            if (m_usedRequests.contains(hash)) {
                qWarning() << "Rejecting second call!";
                return QByteArray();
            }
            m_usedRequests.insert(hash);
            return Rsa::decrypt(m_privKey,QBigInt::fromBigEndianBytes(cipherText)).toBigEndianBytes();
        }

        const Rsa::PubKey & pubKey() const {return m_pubKey; }
    private:
        Rsa::PrivKey m_privKey;
        Rsa::PubKey m_pubKey;
        QSet<QByteArray> m_usedRequests;
    };
}


void TestSet6::testChallenge41()
{
    Server serv;

    const QByteArray message ="{time: 1356304276,social: '555-55-5555'}";

    const QByteArray cipherText = Rsa::encrypt(serv.pubKey(),QBigInt::fromBigEndianBytes(message)).toBigEndianBytes();
    QCOMPARE(serv.request(cipherText),message);

    // Second attempt should be rejected
    QVERIFY(serv.request(cipherText).isNull());

    // Now create a modified copy;
    const QBigInt c = QBigInt::fromBigEndianBytes(cipherText);
    const QBigInt N = serv.pubKey().n;
    const QBigInt E = serv.pubKey().e;
    const QBigInt s = QBigInt::fromBigEndianBytes("somerandombytes") % N;
    //C' = ((S**E mod N) C) mod N
    const QBigInt c1 = (s.powm(E,N) * c) % N;

    const QByteArray p1 = serv.request(c1.toBigEndianBytes());
    QVERIFY(!p1.isEmpty());

    const QBigInt p = (QBigInt::fromBigEndianBytes(p1) / s ) % N;

    const QByteArray hackedPlain = p.toBigEndianBytes();
    qDebug() << "Recovered plain" << hackedPlain;
    QCOMPARE(hackedPlain, message);

}


namespace {
    class SignAndVerify {
    public:
        SignAndVerify()  {
            Rsa::KeyPair keys = Rsa::rsaKeyGen(1024);
            m_privKey = keys.second;
            m_pubKey = keys.first;
        }

        QByteArray pkcs1_5Pad(const QByteArray & data, const int sz)
        {
            const QByteArray pad1 = QByteArray::fromHex("0001");
            const QByteArray pad2 = QByteArray::fromHex("00") + "ASN.1";

            const int padLen = sz - pad1.size() - pad2.size();
            const QByteArray padded = pad1 + QByteArray(padLen,(char)0xff) + pad2 + data;
            return padded;
        }

        QByteArray signContent(const QByteArray & data)
        {
            const QByteArray hashOfData = digest(data);
            const int numBytes = (1024) / 8;

            const QByteArray paddedData = pkcs1_5Pad(hashOfData, numBytes);

            return Rsa::decrypt(m_privKey,
                     QBigInt::fromBigEndianBytes(paddedData))
                    .toBigEndianBytes();
        }

        bool verifyBadly(const QByteArray & signature, const QByteArray & message) const
        {
            const QByteArray hashOfData = digest(message);
            const QByteArray pad2 = QByteArray::fromHex("00") + "ASN.1" + hashOfData;

            const QByteArray testBytes = Rsa::encrypt(m_pubKey, QBigInt::fromBigEndianBytes(signature)).toBigEndianBytes();

            if (testBytes.size() < 8) {
                return false;
            }
            // Leading zeros will be dropped.
            if ( (testBytes.at(0) != 1) || (testBytes.at(1) != (char)0xff) ) {
                return false;
            }
            int i = 2;
            while (testBytes.at(i) == (char)0xff) {
                ++i;
                if (i > (testBytes.size() - pad2.size()) ) {
                    qDebug() << "oob" << testBytes.size() << pad2.size();
                    return false;
                }
            }
            return (testBytes.mid(i,pad2.size()) == pad2);
        }

        const Rsa::PubKey & pubKey() const {return m_pubKey; }

        // Using Md5 because Sha1 hashes are too long for this attack.
        static QByteArray digest(const QByteArray & data) {
            return QCryptographicHash::hash(data, QCryptographicHash::Md5);
        }
    private:
        Rsa::PrivKey m_privKey;
        Rsa::PubKey m_pubKey;
    };
}

void TestSet6::testChallenge42()
{
    
    const QByteArray message = "hi mom";
    
    SignAndVerify signer;
    const QByteArray signature = signer.signContent(message);

    // Check a genuine signature works.
    QVERIFY(signer.verifyBadly(signature, message ));

    // Now fake one.
    const QByteArray hashOfMessage = SignAndVerify::digest(message);

    const QByteArray pad2 = QByteArray::fromHex("01FFFF00") + "ASN.1" + hashOfMessage;

    // We're looking for a number which is the cube root of the target above.

    QBigInt anum = QBigInt::fromBigEndianBytes(pad2);

    // Cubing will not overflow if the high bit is less than highBit(N)/3.
    // Round down to next whole byte.
    int padCount = ( (signer.pubKey().n.highBitPosition()/(3*8)) - pad2.size() )*8;

    // Let's add some (right) padding of fff's since cube-rooting rounds down.
    anum <<= padCount;
    for (int i=0; i<padCount; ++i) {
        anum.setBit(i);
    }

    // Double check we didn't overflow.
    QVERIFY( (anum*anum*anum) < signer.pubKey().n);

    // Cube root
    typedef QPair<QBigInt,QBigInt> BigIntPair;
    const BigIntPair rootrem = anum.nthRootRem(3);

    // Check that cubing back up gives the correct initial bytes.
    const QBigInt fakeSignatureInt = rootrem.first;
    QCOMPARE( (fakeSignatureInt.pow(QBigInt(3)) >> padCount).toBigEndianBytes(),
              pad2);

    QByteArray fakeSignature = fakeSignatureInt.toBigEndianBytes();
    QVERIFY(signer.verifyBadly(fakeSignature, message ));

    qDebug() << "Fake signature is good"; //if we got here.
}

namespace {
    class ParityOracle {
    public:
        ParityOracle() {
            Rsa::KeyPair keys = Rsa::rsaKeyGen(1024);
            m_privKey = keys.second;
            m_pubKey = keys.first;
        }

        bool isOdd(const QBigInt & enc) {
            const QBigInt dec = Rsa::decrypt(m_privKey,enc);
            return dec.testBit(0);
        }

        const Rsa::PubKey & pubKey() const { return m_pubKey; }
    private:
        Rsa::PrivKey m_privKey;
        Rsa::PubKey m_pubKey;
    };

}
void TestSet6::testChallenge46()
{
    const QByteArray message =
    QByteArray::fromBase64(
        "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoI"
        "HRoZSBGdW5reSBDb2xkIE1lZGluYQ==");

    ParityOracle oracle;

    const QBigInt enc = Rsa::encrypt(oracle.pubKey(), QBigInt::fromBigEndianBytes(message));

    // 2**e % n;
    const QBigInt enc2 = QBigInt(2).powm(oracle.pubKey().e, oracle.pubKey().n);

    QBigInt encMult = enc;
    const int itCount = oracle.pubKey().n.highBitPosition();

    const int shift = (((itCount + 7)/8)*8);
    QBigInt nb = oracle.pubKey().n << shift;
    QBigInt ubound = nb;
    QBigInt lbound = QBigInt::zero();

    for (int i=0; i<itCount; ++i){
        encMult *= enc2; // Times 2.
        encMult = encMult % oracle.pubKey().n;
        nb >>= 1;

        if (oracle.isOdd(encMult) ) {
            lbound += nb;
        } else {
            ubound -= nb;
        }
        if (i % 32 == 0)
        {
            // "Hollywood Style"
            qDebug() << "u" << (ubound >> shift).toBigEndianBytes();
        }
    }

    ubound >>= shift;
    lbound >>= shift;
    qDebug() << (ubound).toBigEndianBytes();
    qDebug() << (lbound).toBigEndianBytes();

    const QBigInt result = ubound;

    qDebug() << "Final:" << ubound.toBigEndianBytes();

    QCOMPARE(result.toBigEndianBytes() , message);
    QVERIFY(ubound >= lbound);
}
