#include "testSet5_srp.h"

#include <utils.h>
#include <qbigint.h>
#include <hmac.h>

#include <QByteArray>
#include <QCryptographicHash>
#include <QDebug>
#include <QTest>

#include "test.h"

JDS_ADD_TEST(TestSet5_Srp)

namespace {
    const char * const nist_p =
            "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
            "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
            "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
            "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
            "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
            "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
            "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
            "fffffffffffff";

    QBigInt randomValue(const QBigInt & mx)
    {
        return QBigInt::fromLittleEndianBytes(
                    qossl::randomBytes(mx.highBitPosition() / CHAR_BIT + 1) ) % mx;
    }

    QBigInt hashAndToInt(const QByteArray & data)
    {
        const QByteArray xH = QCryptographicHash::hash(data,QCryptographicHash::Sha256);
        return QBigInt::fromLittleEndianBytes(xH);
    }
}
void TestSet5_Srp::initTestCase()
{
}

void TestSet5_Srp::cleanupTestCase()
{
}

namespace {
    class SrpServer {
    public:
        SrpServer() :
            m_g(2), m_k(3),
            m_N(QBigInt::fromString(nist_p,16)),
            m_privKey(randomValue(m_N))
         {
            this->addUser("joeBlogs@example.com","secret-password");
        }

        QPair<QByteArray, QBigInt> handshake(const QString & user, const QBigInt & A){
            typedef QPair<QByteArray, QBigInt> HandshakeRetType;
            const QByteArray userN = user.normalized(QString::NormalizationForm_C).toUtf8();
            const UserDetail detail = this->m_users.value(userN, UserDetail());

            const QByteArray salt = detail.salt;
            const QBigInt v = QBigInt::fromLittleEndianBytes(detail.v);
            // B=kv + g**b % N
            const QBigInt B = QBigInt(m_k) * v
                    + QBigInt(m_g).modExp(m_privKey,m_N);

            // uH = SHA256(A|B), u = integer of uH
            const QBigInt u = hashAndToInt(A.toLittleEndianBytes() + B.toLittleEndianBytes());

            // S = (A * v**u) ** b % N
            const QBigInt S = (A * v.modExp(u,m_N)).modExp(m_privKey,m_N);

            const QByteArray K = QCryptographicHash::hash(S.toLittleEndianBytes(),QCryptographicHash::Sha256);
            m_clientHash = qossl::hmacSha256(K,salt);

            return HandshakeRetType(detail.salt, B);
        }

        bool verify(const QByteArray & clientHash) const {
            return clientHash == m_clientHash;
        }


    private:
        void addUser(const QString & user, const QString & pass){
            const QByteArray userN = user.normalized(QString::NormalizationForm_C).toUtf8();
            const QByteArray passN = pass.normalized(QString::NormalizationForm_C).toUtf8();

            const QByteArray salt = qossl::randomBytes(16);
            const QBigInt x = hashAndToInt( salt + passN );
            // v=g**x % N
            const QBigInt v = QBigInt(m_g).modExp(x,m_N);
            UserDetail detail;
            detail.salt = salt;
            detail.v = v.toLittleEndianBytes();
            m_users[userN] = detail;
        }
    private:
        struct UserDetail {
            QByteArray salt;
            QByteArray v;
        };

        QHash< QByteArray , UserDetail > m_users;
        const unsigned int m_g, m_k;
        const QBigInt m_N;
        const QBigInt m_privKey;

        QByteArray m_clientHash;
    };

    class SrpClient {
    public:
        SrpClient() :
            m_g(2), m_k(3),
            m_N(QBigInt::fromString(nist_p,16)),
            m_privKey(randomValue(m_N))
        {
        }

        bool verify(SrpServer & server, const QString & user, const QString & pass)
        {
            QBigInt A = QBigInt(m_g).modExp(m_privKey, m_N);
            QPair<QByteArray, QBigInt> resp = server.handshake(user, A);

            const QByteArray userN = user.normalized(QString::NormalizationForm_C).toUtf8();
            const QByteArray passN = pass.normalized(QString::NormalizationForm_C).toUtf8();

            const QByteArray salt = resp.first;
            const QBigInt B = resp.second;

            const QBigInt x = hashAndToInt(salt + passN);

            const QBigInt u = hashAndToInt(A.toLittleEndianBytes() + B.toLittleEndianBytes());

            // S = (B - k * g**x)**(a + u * x) % N
            // S = (B - k * (g**x %N))**(a + u * x) % N
            const QBigInt S = (B - QBigInt(m_k) * QBigInt(m_g).modExp(x,m_N)).modExp(m_privKey + (u * x), m_N);

            const QByteArray K = QCryptographicHash::hash(S.toLittleEndianBytes(), QCryptographicHash::Sha256);

            const QByteArray hmac = qossl::hmacSha256(K,salt);

            qDebug() << "Verifying with mac" << hmac.toHex().left(16) + "...";
            return server.verify(hmac);
        }

    private:
        const unsigned int m_g, m_k;
        const QBigInt m_N;
        const QBigInt m_privKey;
    };
}
void TestSet5_Srp::testChallenge36()
{
    SrpServer server;

    SrpClient client;

    // Good user
    QVERIFY(client.verify(server, "joeBlogs@example.com","secret-password"));

    // Unknown user
    QVERIFY(!client.verify(server, "notThere@iambadass.com", "fake"));

    // Bad password
    QVERIFY(!client.verify(server, "joeBlogs@example.com","not the password"));

    // Bad password (empty)
    QVERIFY(!client.verify(server, "joeBlogs@example.com", QString()));

    // Bad user (empty)
    QVERIFY(!client.verify(server, QString(), "bad"));

    // Bad user and pass (empty)
    QVERIFY(!client.verify(server, QString(), QString()));

    // Good user (again, just to make sure the failed attempts didn't corrupt).
    QVERIFY(client.verify(server, "joeBlogs@example.com","secret-password"));
}
