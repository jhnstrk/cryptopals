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
        return QBigInt::fromLittleEndianBytes(
                    qossl::randomBytes(mx.highBitPosition() / CHAR_BIT + 1) ) % mx;
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
    const QBigInt p( QBigInt::fromString(nist_p , 16) );
    const QBigInt g(5);

    // Generate "a", a random number mod p.
    QBigInt a = randomValue(p);
    a = QBigInt::fromString(
    "34df8dd5c40ce79bbdef742531dc0a0a585ef948c98124cb18cda27af0521c6791a222bf4a"
    "119d44f267b00273b1e5c6eb3d382c82c87078fec0295cfcdda67255008290b5bf250ac56c"
    "e40b3f1e30291cbe6b5bcbbd0d9b9d751330795f21ce47487dcb96b9abfd5ab56355b786ff"
    "54368c78a36017bc92193f321655a7bc7d8e57e4a7526ee9767ad7f0f98bd2e7e92e7ceeaa"
    "ca12d55e0223ccf49f7db9ae27a538aed133d0bf81a0bc4e0e93a07e96f8fca896955e9533"
    "d6b504a77f4dc7",16);

    // Now generate "A", which is "g" raised to the "a" power mod p --- A = (g**a) % p.
    QBigInt A = g.modExp(a,p);

    // Do the same for "b" and "B".
    QBigInt b = randomValue(p);
    b = QBigInt::fromString(
    "a2380c33e714ae0c9dce5b279b21f5e290f54eb6c84ad11a3cf50fac58ec2000cdf367d11a"
    "01965465ba89149711c4848123ea23353d10cf2840a26df2c83b058ff2976f066a0ad45b5b"
    "aaeab7781381d9306705bbc97caff7f15dc75d812ce1f9f44d136aa59291236de026592ac2"
    "22939f37713391099348015c32b32f0049d82d4796a9c0e33340a348a110ea03620773eb8c"
    "0da1a9033e58f582004625426a5d384dc579b573df8a3613e524299e23252b17d0f7734866"
    "f7784832e68bf2",16);

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


namespace Challenge34 {

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
            m_p( QBigInt::fromString(QString(nist_p) , 16)),
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
    using namespace Challenge34;
    Alice a;
    Bob b;
    a.sendDHParam(b);
    b.sendPublicKey(a);
    a.sendEncryptedMessage(b);
    b.sendEncryptedMessage(a);
}

namespace Challenge34 {
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
    using namespace Challenge34;
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


namespace Challenge35 {

    class IAlice {
    public:
        virtual void receiveAck(const int ack) = 0;
        virtual void receivePeerPubKey(const QBigInt & B) = 0;
        virtual void receiveEncryptedMessage(const QByteArray & iv, const QByteArray & enc) = 0;
    };

    class IBob {
    public:
        virtual void receiveDHParam(const QBigInt & p, const QBigInt & g) =0;
        virtual void receivePeerPubKey(const QBigInt & A) = 0;
        virtual void receiveEncryptedMessage(const QByteArray & iv, const QByteArray & enc) = 0;
    };

    class Alice : public IAlice{
    public:
        Alice() :
            m_p( QBigInt::fromString(QString(nist_p) , 16)),
            m_g(5)
        {
        }

        virtual ~Alice() {}
        void sendDHParam(IBob & b) Q_DECL_OVERRIDE
        {
            m_a = randomValue(m_p);  // Private key
            m_A = m_g.modExp(m_a,m_p);  // Public key
            b.receiveDHParam(m_p,m_g);
        }

        virtual void receiveAck(int) Q_DECL_OVERRIDE { }

        void sendPublicKey(IBob & b)
        {
            b.receivePeerPubKey(m_A);
        }

        virtual void receivePeerPubKey(const QBigInt & B) Q_DECL_OVERRIDE
        {
            m_B = B;
            m_s = qossl::Sha1::hash(m_B.modExp(m_a,m_p).toLittleEndianBytes());
            m_s = m_s.left(qossl::AesBlockSize);
            qDebug() << "Alice key" << m_s << m_B;
        }

        void sendEncryptedMessage(IBob & b)
        {
            const QByteArray message = "Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection";
            const QByteArray iv = qossl::randomBytes(qossl::AesBlockSize);
            const QByteArray enc = qossl::aesCbcEncrypt(qossl::pkcs7Pad(message,qossl::AesBlockSize),m_s,iv);
            b.receiveEncryptedMessage(iv,enc);
        }

        virtual void receiveEncryptedMessage(const QByteArray & iv, const QByteArray & enc) Q_DECL_OVERRIDE
        {
            const QByteArray message = qossl::pkcs7Unpad(qossl::aesCbcDecrypt(enc,m_s,iv));
            qDebug() << "Alice got message" << message;
        }

    private:
        QBigInt m_B;
        QBigInt m_p, m_g, m_a, m_A;
        QByteArray m_s; // Session key
    };

    class Bob : public IBob{
    public:
        Bob() {}
        virtual ~Bob() {}

        virtual void receiveDHParam(const QBigInt & p, const QBigInt & g) Q_DECL_OVERRIDE
        {
            m_p = p;
            m_g = g;

            m_b = randomValue(m_p);  // Private key
            m_B = m_g.modExp(m_b,m_p);  // Public key
        }

        virtual void receivePeerPubKey(const QBigInt & A) Q_DECL_OVERRIDE
        {
            m_A = A;
            m_s = qossl::Sha1::hash(m_A.modExp(m_b,m_p).toLittleEndianBytes());
            m_s = m_s.left(qossl::AesBlockSize);
            qDebug () << "Bob key" << m_s << m_A;
        }

        void sendAck(IAlice & a)
        {
            a.receiveAck(1);
        }

        void sendPublicKey(IAlice & a)
        {
            a.receivePeerPubKey(m_B);
        }

        virtual void receiveEncryptedMessage(const QByteArray & iv, const QByteArray & enc) Q_DECL_OVERRIDE
        {
            const QByteArray message = qossl::pkcs7Unpad(qossl::aesCbcDecrypt(enc,m_s,iv));
            qDebug() << "Bob got message" << message;
            m_message = message;
        }

        void sendEncryptedMessage(IAlice & a)
        {
            const QByteArray iv = qossl::randomBytes(qossl::AesBlockSize);
            const QByteArray enc = qossl::aesCbcEncrypt(qossl::pkcs7Pad(m_message,qossl::AesBlockSize),m_s,iv);
            a.receiveEncryptedMessage(iv,enc);
        }

    private:
        QBigInt m_A;
        QBigInt m_p, m_g, m_b, m_B;
        QByteArray m_s; // Session key
        QByteArray m_message;
    };

    // Base class is just pass-through.
    class Mallory : public IAlice, public IBob {
    public:
        Mallory(Alice & a, Bob & b)
            : m_alice(a), m_bob(b),m_count(0)
        {
        }

        virtual void receiveDHParam(const QBigInt & p, const QBigInt & g) Q_DECL_OVERRIDE
        {
            // Take a copy.
            m_p = p;
            m_g = g;

            // Mess with parameters.
            m_bob.receiveDHParam(p,g);
        }

        virtual void receiveAck(int ack) Q_DECL_OVERRIDE
        {
            m_alice.receiveAck(ack);
        }

        virtual void receivePeerPubKey(const QBigInt & pk) Q_DECL_OVERRIDE
        {
            if (m_count & 1) {
                m_alice.receivePeerPubKey(pk);
                m_B = pk;
            } else {
                m_bob.receivePeerPubKey(pk);
                m_A = pk;
            }

            ++m_count;
        }

        virtual void receiveEncryptedMessage(const QByteArray & iv, const QByteArray & enc) Q_DECL_OVERRIDE
        {
            if (m_count & 1) {
                m_alice.receiveEncryptedMessage(iv,enc);
            } else {
                m_bob.receiveEncryptedMessage(iv,enc);
            }
            if (!m_s.isNull()) {
                const QByteArray message = qossl::pkcs7Unpad(qossl::aesCbcDecrypt(enc,m_s,iv));
                qDebug() << "Mallory read message" << message;
            }
            ++m_count;
        }

    protected:
        Alice & m_alice;
        Bob & m_bob;

        QBigInt m_p;
        QBigInt m_g;
        QBigInt m_A, m_B;
        unsigned int m_count;
        QByteArray m_s;
    };


    // Fix g=1
    // This means that the public key is both 1**x => 1.
    // For this to work, we fake the public key of Alice too, setting it to one.
    class MalloryG1 : public Mallory {
    public:
        MalloryG1(Alice & a, Bob & b) : Mallory(a,b)
        {
            m_s = qossl::Sha1::hash(QBigInt::one().toLittleEndianBytes());
            m_s = m_s.left(qossl::AesBlockSize);
        }

        virtual void receiveDHParam(const QBigInt & p, const QBigInt & g) Q_DECL_OVERRIDE
        {
            // Take a copy.
            m_p = p;
            m_g = g;

            // Mess with parameters.
            m_bob.receiveDHParam(p,QBigInt::one());
        }

        virtual void receivePeerPubKey(const QBigInt & pk) Q_DECL_OVERRIDE
        {
            if (m_count & 1) {
                m_alice.receivePeerPubKey(pk);
                m_B = pk;
            } else {
                m_bob.receivePeerPubKey(QBigInt::one());
                m_A = pk;
            }

            ++m_count;
        }
    };

    // Fix g=p
    // This means that the public keys are always zero since (x ** N mod x) == 0,
    // and the session key will be hash-of-zero.
    // For this to work, we fake the public key of Alice too, setting it to zero.
    class MalloryGP : public Mallory {
    public:
        MalloryGP(Alice & a, Bob & b) : Mallory(a,b)
        {
            m_s = qossl::Sha1::hash(QBigInt::zero().toLittleEndianBytes());
            m_s = m_s.left(qossl::AesBlockSize);
        }

        virtual void receiveDHParam(const QBigInt & p, const QBigInt & g) Q_DECL_OVERRIDE
        {
            // Take a copy.
            m_p = p;
            m_g = g;

            // Mess with parameters.
            m_bob.receiveDHParam(p,p);  // g = p
        }

        virtual void receivePeerPubKey(const QBigInt & pk) Q_DECL_OVERRIDE
        {
            if (m_count & 1) {
                m_alice.receivePeerPubKey(pk);
                m_B = pk;
            } else {
                m_bob.receivePeerPubKey(QBigInt::zero());
                m_A = pk;
            }

            ++m_count;
        }
    };

    // Fix g=p-1
    // This means that the public keys are either 1 or p-1;
    // pub key = g ** priv key % p;
    //    (p-1) ** X == (p-1)(p-1)(...) %p
    //               == (p**2 -2p +1)(...) %p
    //               == 1.(...) %p
    // Whether the public key is 1 or p-1 depends on the last bit of the private key.
    class MalloryGPm1 : public Mallory {
    public:
        MalloryGPm1(Alice & a, Bob & b) : Mallory(a,b)
        {
        }

        virtual void receiveDHParam(const QBigInt & p, const QBigInt & g) Q_DECL_OVERRIDE
        {
            // Take a copy.
            m_p = p;
            m_g = g;

            // Mess with parameters.
            m_bob.receiveDHParam(p,(p - 1));  // g = p - 1
        }

        virtual void receivePeerPubKey(const QBigInt & pk) Q_DECL_OVERRIDE
        {
            if (m_count & 1) {
                m_alice.receivePeerPubKey(QBigInt::one());
                m_B = pk;
            } else {
                m_bob.receivePeerPubKey(QBigInt::one());
                m_A = pk;
            }

            ++m_count;
        }

        virtual void receiveEncryptedMessage(const QByteArray & iv, const QByteArray & enc) Q_DECL_OVERRIDE
        {
            m_s = qossl::Sha1::hash(QBigInt::one().toLittleEndianBytes());
            m_s = m_s.left(qossl::AesBlockSize);

            if (m_count & 1) {
                m_alice.receiveEncryptedMessage(iv,enc);
            } else {
                m_bob.receiveEncryptedMessage(iv,enc);
            }
            if (!m_s.isNull()) {
                const QByteArray message = qossl::pkcs7Unpad(qossl::aesCbcDecrypt(enc,m_s,iv));
                qDebug() << "Mallory read message" << message;
            }
            ++m_count;
        }
    };
}

void TestSet5::testChallenge35()
{
    using namespace Challenge35;

    Alice a;
    Bob b;
    a.sendDHParam(b);
    b.sendAck(a);
    a.sendPublicKey(b);
    b.sendPublicKey(a);
    a.sendEncryptedMessage(b);
    b.sendEncryptedMessage(a);
}

void TestSet5::testChallenge35_g_1()
{
    using namespace Challenge35;

    Alice a;
    Bob b;
    MalloryG1 m(a,b);
    a.sendDHParam(m);
    b.sendAck(m);
    a.sendPublicKey(m);
    b.sendPublicKey(m);
    a.sendEncryptedMessage(m);
    b.sendEncryptedMessage(m);
}

void TestSet5::testChallenge35_g_p()
{
    using namespace Challenge35;

    Alice a;
    Bob b;
    MalloryGP m(a,b);
    a.sendDHParam(m);
    b.sendAck(m);
    a.sendPublicKey(m);
    b.sendPublicKey(m);
    a.sendEncryptedMessage(m);
    b.sendEncryptedMessage(m);
}

void TestSet5::testChallenge35_g_pm1()
{
    using namespace Challenge35;

    Alice a;
    Bob b;
    MalloryGPm1 m(a,b);
    a.sendDHParam(m);
    b.sendAck(m);
    a.sendPublicKey(m);
    b.sendPublicKey(m);
    a.sendEncryptedMessage(m);
    b.sendEncryptedMessage(m);
}


