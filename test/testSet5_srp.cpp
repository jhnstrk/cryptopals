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
        return QBigInt::fromBigEndianBytes(
                    qossl::randomBytes(mx.highBitPosition() / CHAR_BIT + 1) ) % mx;
    }

    QBigInt hashAndToInt(const QByteArray & data)
    {
        const QByteArray xH = QCryptographicHash::hash(data,QCryptographicHash::Sha256);
        return QBigInt::fromBigEndianBytes(xH);
    }

    QByteArray sha256Hash(const QByteArray & data) {
        return QCryptographicHash::hash(data, QCryptographicHash::Sha256);
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
            const QBigInt v = QBigInt::fromBigEndianBytes(detail.v);
            // B=kv + g**b % N
            const QBigInt B = QBigInt(m_k) * v
                    + QBigInt(m_g).powm(m_privKey,m_N);

            // uH = SHA256(A|B), u = integer of uH
            const QBigInt u = hashAndToInt(A.toBigEndianBytes() + B.toBigEndianBytes());

            // S = (A * v**u) ** b % N
            const QBigInt S = (A * v.powm(u,m_N)).powm(m_privKey,m_N);

            const QByteArray K = sha256Hash(S.toBigEndianBytes());
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
            const QBigInt v = QBigInt(m_g).powm(x,m_N);
            UserDetail detail;
            detail.salt = salt;
            detail.v = v.toBigEndianBytes();
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
            m_g(2),m_k(3),
            m_N(QBigInt::fromString(nist_p,16)),
            m_privKey(randomValue(m_N))
        {
        }

        virtual ~SrpClient() {}

        virtual bool verify(SrpServer & server, const QString & user, const QString & pass)
        {
            QBigInt A = this->getA();
            QPair<QByteArray, QBigInt> resp = server.handshake(user, A);

            const QByteArray userN = user.normalized(QString::NormalizationForm_C).toUtf8();
            const QByteArray passN = pass.normalized(QString::NormalizationForm_C).toUtf8();

            const QByteArray salt = resp.first;
            const QBigInt B = resp.second;

            const QBigInt x = hashAndToInt(salt + passN);

            const QBigInt u = hashAndToInt(A.toBigEndianBytes() + B.toBigEndianBytes());

            const QBigInt S = this->getS(B,u,x);
            const QByteArray K = sha256Hash(S.toBigEndianBytes());

            const QByteArray hmac = qossl::hmacSha256(K,salt);

            qDebug() << "Verifying with mac" << hmac.toHex().left(16) + "...";
            return server.verify(hmac);
        }

    protected:
        virtual QBigInt getA() const {
            return  QBigInt(m_g).powm(m_privKey, m_N);
        }

        virtual QBigInt getS(const QBigInt & B, const QBigInt & u, const QBigInt & x) const {
            // S = (B - k * g**x)**(a + u * x) % N
            // S = (B - k * (g**x %N))**(a + u * x) % N
            return (B - QBigInt(m_k) * QBigInt(m_g).powm(x,m_N)).powm(m_privKey + (u * x), m_N);
        }
    protected:
        const unsigned int m_g,m_k;
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


namespace {
class BadSrpClient: public SrpClient {
public:
    BadSrpClient(int multipleA) : SrpClient(), m_multipleA(multipleA) {}

protected:
    virtual QBigInt getA() const Q_DECL_OVERRIDE {
        return m_N * QBigInt(m_multipleA);
        // return  QBigInt(m_g).powm(m_privKey, m_N);
    }

    virtual QBigInt getS(const QBigInt &, const QBigInt &, const QBigInt &) const Q_DECL_OVERRIDE {
        // S = (B - k * g**x)**(a + u * x) % N
        return QBigInt::zero();
    }
private:
    unsigned int m_multipleA;
};

} // anon

void TestSet5_Srp::testChallenge37()
{
    // Sending A as zero means that the server will always compute the S value to be zero.
    // This is also true for any multiple of N, since A % N will be zero too.
    SrpServer server;

    BadSrpClient client(0);

    // Good user
    QVERIFY(client.verify(server, "joeBlogs@example.com","secret-password"));

    // Unknown user
    QVERIFY(client.verify(server, "notThere@iambadass.com", "fake"));

    // A = N
    BadSrpClient client1(1);
    QVERIFY(client1.verify(server, "notThere@iambadass.com", "fake"));

    // A = 2N
    BadSrpClient client2(2);
    QVERIFY(client2.verify(server, "notThere@iambadass.com", "fake"));
}


namespace {

class ISimpleSrpServer {
public:
    virtual ~ISimpleSrpServer() {}

    struct HandshakeRetType {
        QByteArray salt;
        QBigInt B;
        QBigInt u;
    };

    virtual HandshakeRetType handshake(const QString & user, const QBigInt & A) = 0;
    virtual bool verify(const QByteArray & clientHash) const = 0;
};

class SimpleSrpServer : public ISimpleSrpServer
{
public:
    SimpleSrpServer() :
        m_g(2),
        m_N(QBigInt::fromString(nist_p,16)),
        m_privKey(randomValue(m_N))
    {
        this->addUser("joeBlogs@example.com","secret-password");
    }

    virtual ~SimpleSrpServer() {}

    virtual HandshakeRetType handshake(const QString & user, const QBigInt & A){
        const QByteArray userN = user.normalized(QString::NormalizationForm_C).toUtf8();
        const UserDetail detail = this->m_users.value(userN, UserDetail());

        HandshakeRetType ret;
        ret.salt = detail.salt;
        // salt, B = g**b % n, u = 128 bit random number
        ret.B = QBigInt(m_g).powm(m_privKey,m_N);
        ret.u = QBigInt::fromBigEndianBytes(qossl::randomBytes(128/8));

        const QBigInt v = QBigInt::fromBigEndianBytes(detail.v);
        // S = (A * v ** u)**b % n
        // K = SHA256(S)
        const QBigInt S = (A * v.powm(ret.u,m_N)).powm(m_privKey,m_N);
        const QByteArray K = sha256Hash(S.toBigEndianBytes());
        m_clientHash = qossl::hmacSha256(K,ret.salt);

        return ret;
    }

    virtual bool verify(const QByteArray & clientHash) const {
        return clientHash == m_clientHash;
    }


private:
    void addUser(const QString & user, const QString & pass){
        const QByteArray userN = user.normalized(QString::NormalizationForm_C).toUtf8();
        const QByteArray passN = pass.normalized(QString::NormalizationForm_C).toUtf8();

        //x = SHA256(salt|password)
        const QByteArray salt = qossl::randomBytes(16);
        const QBigInt x = hashAndToInt( salt + passN );
        //v = g**x % n
        const QBigInt v = QBigInt(m_g).powm(x,m_N);
        UserDetail detail;
        detail.salt = salt;
        detail.v = v.toBigEndianBytes();
        m_users[userN] = detail;
    }
private:
    struct UserDetail {
        QByteArray salt;
        QByteArray v;
    };

    QHash< QByteArray , UserDetail > m_users;
    const unsigned int m_g;
    const QBigInt m_N;
    const QBigInt m_privKey;

    QByteArray m_clientHash;
};

class SimpleSrpClient {
public:
    SimpleSrpClient() :
        m_g(2),
        m_N(QBigInt::fromString(nist_p,16)),
        m_privKey(randomValue(m_N))
    {
    }

    virtual ~SimpleSrpClient() {}

    virtual bool verify(ISimpleSrpServer & server, const QString & user, const QString & pass)
    {
        const QBigInt A = QBigInt(m_g).powm(m_privKey, m_N);
        //I, A = g**a % n
        SimpleSrpServer::HandshakeRetType resp = server.handshake(user, A);

        const QByteArray passN = pass.normalized(QString::NormalizationForm_C).toUtf8();
        // x = SHA256(salt|password)
        const QBigInt x = hashAndToInt(resp.salt + passN);

        // S = B**(a + ux) % n
        const QBigInt S = resp.B.powm(m_privKey + resp.u * x, m_N);

        //  K = SHA256(S)
        const QByteArray K = sha256Hash(S.toBigEndianBytes());

        const QByteArray hmac = qossl::hmacSha256(K,resp.salt);

        qDebug() << "Verifying with mac" << hmac.toHex().left(16) + "...";
        return server.verify(hmac);
    }

protected:
    const unsigned int m_g;
    const QBigInt m_N;
    const QBigInt m_privKey;
};

class MitmSimpleServer : public ISimpleSrpServer {
public:
    MitmSimpleServer ()
        : m_g(2),
          m_N(QBigInt::fromString(nist_p,16)),
          m_fixedSalt(QByteArray(1,'A'))
    {}

    virtual HandshakeRetType handshake(const QString & user, const QBigInt & A){

        m_A = A;
        HandshakeRetType ret;
        ret.salt = m_fixedSalt;
        ret.B = QBigInt(m_g);
        ret.u = QBigInt::one();

        m_user = user;
        return ret;
    }

    virtual bool verify(const QByteArray & clientHash) const {
        const_cast<MitmSimpleServer*>(this)->m_clientHash = clientHash;

        return false;
    }


    QByteArray dictionaryAttack() {
        QList< QByteArray> dictionary;
        dictionary << "Not this one" << "qwerty" << "123456"
                   << "secret-password" << "fake";

        // Dictionary attack.
        foreach (const QByteArray & item, dictionary) {
            // x = SHA256(salt|password)
            const QBigInt x = hashAndToInt(m_fixedSalt + item);

            // S = B**(a + ux) % n
            //   = (A * g**x)%n
            const QBigInt S = ( m_A * QBigInt(m_g).powm(x, m_N)) % m_N;

            //  K = SHA256(S)
            const QByteArray K = sha256Hash(S.toBigEndianBytes());

            const QByteArray hmac = qossl::hmacSha256(K,m_fixedSalt);

            if (hmac == m_clientHash) {
                qDebug() << "Recovered password: " << item;
                return item;
            }
        }
        return QByteArray();
    }

private:
    const unsigned int m_g;
    const QBigInt m_N;
    const QByteArray m_fixedSalt;
    QByteArray m_clientHash;
    QString m_user;
    QBigInt m_A;
};
}
void TestSet5_Srp::testChallenge38()
{
    SimpleSrpServer server;

    SimpleSrpClient client;

    // First test that the simple server works.

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


    // Now the MITM attack.
    // The client returns a hash based on
    //   S = B**(a + ux) % n
    //    = (B**a * B**ux) %n
    // and the server controls B, u. Also, n is fixed.
    //
    // The client provides to the server
    // A = g **a %n
    //   and g is fixed.
    //
    // So, if we provide to the client B = g, and u = 1, the client will return
    //  S = (g**a * B**ux) %n
    //    = (A * g**x)%n
    // which are all values we know, apart from x. So we can dictionary attack x.
    MitmSimpleServer hacker;

    // The fake server always rejects clients
    QVERIFY(!client.verify(hacker, "joeBlogs@example.com","secret-password"));

    // Check the dictionary attack worked.
    QCOMPARE(hacker.dictionaryAttack(), QByteArray("secret-password"));
}
