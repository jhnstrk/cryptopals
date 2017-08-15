#include "testSet5.h"

#include <utils.h>
#include <sha_1.h>
#include <qbigint.h>

#include <QByteArray>
#include <QDebug>
#include <QElapsedTimer>
#include <QThread>
#include <QTest>

#include "test.h"

JDS_ADD_TEST(TestSet5)

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
}
void TestSet5::initTestCase()
{

}

void TestSet5::cleanupTestCase()
{

}

namespace {
    quint64 mod_exp(quint64 x, quint64 p, quint64 m)
    {
        if (p == 0) {
            return 1;
        }
        if (m <= 1) {
            return 0;
        }
        quint64 y = x;
        for (quint64 i = 1; i < p; ++i) {
            y *= x;
            y = y % m;
        }
        return y;
    }

    QBigInt randomValue(const QBigInt & mx)
    {
        return QBigInt( qossl::randomBytes(mx.highBitPosition() / CHAR_BIT + 1) ) % mx;
    }
}

void TestSet5::testChallenge33_1()
{
    // Set a variable "p" to 37 and "g" to 5.
    const quint64 p = 37;
    const quint64 g = 5;

    // Generate "a", a random number mod 37.
    quint64 a = qossl::randomUInt() % p;

    // Now generate "A", which is "g" raised to the "a" power mode 37 --- A = (g**a) % p.
    quint64 A = mod_exp(g,a,p);

    // Do the same for "b" and "B".
    quint64 b = qossl::randomUInt() % p;
    quint64 B = mod_exp(g,b,p);

    // "A" and "B" are public keys. Generate a session key with them;
    // set "s" to "B" raised to the "a" power mod 37 --- s = (B**a) % p.
    quint64 s = mod_exp(B,a,p);

    // Do the same with A**b, check that you come up with the same "s".
    quint64 s_a = mod_exp(A,b,p);

    // The point is that users Alice and Bob can exchange a key, s, without having
    // to pass the value in clear.
    QCOMPARE( s, s_a);

    // To turn "s" into a key, you can just hash it to create 128 bits
    // of key material (or SHA256 it to create a key for encrypting and a key for a MAC).
    QByteArray s_key = qossl::Sha1::hash(QByteArray::number(s, 16));
    QVERIFY(!s_key.isNull());
}

void TestSet5::testChallenge33_2()
{
    const QBigInt p( QString(nist_p) , 16);
    const QBigInt g(5);

    // Generate "a", a random number mod p.
    QBigInt a = randomValue(p);

    // Now generate "A", which is "g" raised to the "a" power mode 37 --- A = (g**a) % p.
    QBigInt A = g.modExp(a,p);

    // Do the same for "b" and "B".
    QBigInt b = randomValue(p);
    QBigInt B = g.modExp(b,p);

    // "A" and "B" are public keys. Generate a session key with them;
    // set "s" to "B" raised to the "a" power mod p --- s = (B**a) % p.
    QBigInt s = B.modExp(a,p);

    // Do the same with A**b, check that you come up with the same "s".
    QBigInt s_a = A.modExp(b,p);

    QCOMPARE( s.toString(16), s_a.toString(16) );

    // To turn "s" into a key, you can just hash it to create 128 bits
    // of key material (or SHA256 it to create a key for encrypting and a key for a MAC).
    QByteArray s_key = qossl::Sha1::hash(s.toLittleEndianBytes());
    QVERIFY(!s_key.isNull());
}


namespace {

    class IAlice {
    public:
        virtual void receivePeerPubKey(const QBigInt & B) = 0;
        virtual void receiveEncryptedMessage(const QByteArray & iv, const QByteArray & enc) = 0;
    };

    class IBob {
    public:
        virtual void receiveDHParam(const QBigInt & p, const QBigInt & g, const QBigInt & A) = 0;
        virtual void receiveEncryptedMessage(const QByteArray & iv, const QByteArray & enc) = 0;
    };
    
    class Alice : public IAlice{
    public:
        Alice() :
            m_p( QString(nist_p) , 16),
            m_g(5)
        {
        }
        
        virtual ~Alice() {}
        void sendDHParam(IBob & b) Q_DECL_OVERRIDE;
        virtual void receivePeerPubKey(const QBigInt & B) Q_DECL_OVERRIDE;

        void sendEncryptedMessage(IBob & b);
        virtual void receiveEncryptedMessage(const QByteArray & iv, const QByteArray & enc) Q_DECL_OVERRIDE;

    private:
        QBigInt m_B;
        QBigInt m_p, m_g, m_a, m_A;
        QByteArray m_s; // Session key
    };

    class Bob : public IBob{
    public:
        Bob() {}
        virtual ~Bob() {}
        
        virtual void receiveDHParam(const QBigInt & p, const QBigInt & g, const QBigInt & A);
        
        void sendPublicKey(IAlice & a);

        virtual void receiveEncryptedMessage(const QByteArray & iv, const QByteArray & enc);
        void sendEncryptedMessage(IAlice & b);
    private:
        QBigInt m_A;
        QBigInt m_p, m_g, m_b, m_B;
        QByteArray m_s; // Session key
        QByteArray m_message;
    };

    void Alice::sendDHParam(IBob &b)
    {
        m_a = randomValue(m_p);  // Private key
        m_A = m_g.modExp(m_a,m_p);  // Public key
        b.receiveDHParam(m_p,m_g,m_A);
    }

    void Alice::receivePeerPubKey(const QBigInt &B)
    {
        m_B = B;
        m_s = qossl::Sha1::hash(m_B.modExp(m_a,m_p).toLittleEndianBytes());
        m_s = m_s.left(qossl::AesBlockSize);
    }

    void Alice::sendEncryptedMessage(IBob &b){
        const QByteArray message = "Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection";
        const QByteArray iv = qossl::randomBytes(qossl::AesBlockSize);
        const QByteArray enc = qossl::aesCbcEncrypt(qossl::pkcs7Pad(message,qossl::AesBlockSize),m_s,iv);
        b.receiveEncryptedMessage(iv,enc);
    }

    void Alice::receiveEncryptedMessage(const QByteArray &iv, const QByteArray &enc){
        const QByteArray message = qossl::pkcs7Unpad(qossl::aesCbcDecrypt(enc,m_s,iv));
        qDebug() << "Alice got message" << message;
    }
    void Bob::receiveDHParam(const QBigInt &p, const QBigInt &g, const QBigInt &A)
    {
        m_p = p;
        m_g = g;
        m_A = A;

        m_b = randomValue(m_p);  // Private key
        m_B = m_g.modExp(m_b,m_p);  // Public key

        m_s = qossl::Sha1::hash(m_A.modExp(m_b,m_p).toLittleEndianBytes());
        m_s = m_s.left(qossl::AesBlockSize);
    }

    void Bob::sendPublicKey(IAlice &a){
        a.receivePeerPubKey(m_B);
    }

    void Bob::receiveEncryptedMessage(const QByteArray &iv, const QByteArray &enc){
        const QByteArray message = qossl::pkcs7Unpad(qossl::aesCbcDecrypt(enc,m_s,iv));
        qDebug() << "Bob got message" << message;
        m_message = message;
    }

    void Bob::sendEncryptedMessage(IAlice &a){
        const QByteArray iv = qossl::randomBytes(qossl::AesBlockSize);
        const QByteArray enc = qossl::aesCbcEncrypt(qossl::pkcs7Pad(m_message,qossl::AesBlockSize),m_s,iv);
        a.receiveEncryptedMessage(iv,enc);
    }
}
void TestSet5::testChallenge34_1()
{
    Alice a;
    Bob b;
    a.sendDHParam(b);
    b.sendPublicKey(a);
    a.sendEncryptedMessage(b);
    b.sendEncryptedMessage(a);
}

namespace {
    class Mallory : public IAlice, public IBob {
    public:
        Mallory(Alice & a, Bob & b)
            : m_alice(a), m_bob(b),m_count(0)
        {
            m_s = qossl::Sha1::hash(QBigInt::zero().toLittleEndianBytes());
            m_s = m_s.left(qossl::AesBlockSize);
        }

        virtual void receiveDHParam(const QBigInt & p, const QBigInt & g, const QBigInt & A) Q_DECL_OVERRIDE
        {
            // Take a copy.
            m_p = p;
            m_g = g;
            m_A = A;

            // Mess with parameters.
            m_bob.receiveDHParam(p,g,p);
        }

        virtual void receivePeerPubKey(const QBigInt & B) Q_DECL_OVERRIDE
        {
            m_B = B;
            // Send p instead of public key.
            m_alice.receivePeerPubKey(m_p);
        }
        virtual void receiveEncryptedMessage(const QByteArray & iv, const QByteArray & enc) Q_DECL_OVERRIDE
        {
            if (m_count & 1) {
                m_alice.receiveEncryptedMessage(iv,enc);
            } else {
                m_bob.receiveEncryptedMessage(iv,enc);
            }
            const QByteArray message = qossl::pkcs7Unpad(qossl::aesCbcDecrypt(enc,m_s,iv));
            qDebug() << "Mallory read message" << message;

            ++m_count;
        }

    private:
        Alice & m_alice;
        Bob & m_bob;

        QBigInt m_p;
        QBigInt m_g;
        QBigInt m_A, m_B;
        unsigned int m_count;
        QByteArray m_s;
    };
}

void TestSet5::testChallenge34_2()
{
    Alice a;
    Bob b;
    Mallory m(a,b);
    a.sendDHParam(m);
    b.sendPublicKey(m);
    a.sendEncryptedMessage(m);
    b.sendEncryptedMessage(m);

    // Theory:
    // By setting the public key to 'p' the session key will become the sha1-hash of zero;
    // since p % p == 0, raising p to any power x (mod p) is always zero.
}

