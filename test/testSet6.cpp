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
    const QBigInt c1 = (s.modExp(E,N) * c) % N;

    const QByteArray p1 = serv.request(c1.toBigEndianBytes());
    QVERIFY(!p1.isEmpty());

    const QBigInt p = (QBigInt::fromBigEndianBytes(p1) / s ) % N;

    const QByteArray hackedPlain = p.toBigEndianBytes();
    qDebug() << "Recovered plain" << hackedPlain;
    QCOMPARE(hackedPlain, message);

}
