#include "testSet7_CBC_MAC.h"

#include <qbigint.h>
#include <utils.h>

#include <QDebug>
#include <QTest>

#include "test.h"

JDS_ADD_TEST(TestSet7_CBC_MAC)

namespace {

// Compute the CBC Mac.
QByteArray cbcMac(const QByteArray & data,const QByteArray & key,const QByteArray & iv) {
    QByteArray padData = qossl::pkcs7Pad(data,qossl::AesBlockSize);
    const QByteArray enc = qossl::aesCbcEncrypt(padData,key,iv);
    return enc.right(qossl::AesBlockSize);
}


class BankingServer {
public:
    BankingServer() :
        m_key("yellow submarine")
    {}

    // Parse and perform message.
    // Message of form "message || IV || MAC"
    bool doTransaction(const QByteArray & message) {
        // Need iv + mac or it's invalid.
        if (message.size() < 2*qossl::AesBlockSize) {
            return false;
        }
        const QByteArray mac = message.mid(message.size() - qossl::AesBlockSize, qossl::AesBlockSize);
        const QByteArray iv = message.mid(message.size() - 2*qossl::AesBlockSize, qossl::AesBlockSize);
        const QByteArray content = message.left(message.size() - 2*qossl::AesBlockSize);

        // Is the IV included in the MAC computation?
        // Including it would be more secure.
        const QByteArray expectedMac = cbcMac(content, m_key, iv);
        if (expectedMac != mac) {
            qWarning() << "Invalid Mac";
            return false;
        }

        qDebug() << "Performing action" << content;
        return true;
    }

    QByteArray key() const { return m_key; }
private:
    const QByteArray m_key;    // Private Key
};

class BankingClient {
public:
    BankingClient() :
        m_key("yellow submarine"),
        m_userId("Alice")
    {}

    QByteArray createMessage(const QByteArray &to, unsigned int amount) const
    {
        const QByteArray data = "from=" + m_userId + "&to=" + to + "&amount=" +
                QByteArray::number(amount);
        const QByteArray iv = qossl::randomBytes(qossl::AesBlockSize);
        const QByteArray mac = cbcMac(data,m_key,iv);
        return data + iv + mac;
    }

private:
    const QByteArray m_key;     // Private Key
    const QByteArray m_userId;
};
}

void TestSet7_CBC_MAC::testChallenge49_basic()
{
    BankingServer server;
    QVERIFY(!server.doTransaction("")); // Invalid
    QVERIFY(!server.doTransaction("Give me all the money in the world because I need it.")); // Invalid

    const QByteArray data = "from=Alice&to=Bob&amount=100";
    const QByteArray iv = qossl::randomBytes(qossl::AesBlockSize);
    const QByteArray notKey = "green  submarine";
    const QByteArray mac1 = cbcMac(data,notKey,iv);

    QVERIFY(!server.doTransaction(data + iv + mac1));  // invalid (bad key)

    const QByteArray mac2 = cbcMac(data,server.key(),iv);
    QVERIFY(server.doTransaction(data + iv + mac2));  // Should be ok

    BankingClient client;
    QVERIFY(server.doTransaction(client.createMessage("Charlie",500)));  // Should be ok
}

void TestSet7_CBC_MAC::testChallenge49()
{
    BankingClient client;
    // Create a valid message requesting transfer from Alice (which we control) to
    // Mallory of 1000000 space bucks.
    QByteArray msg = client.createMessage("Mallory", 1000000);

    const int BSz = qossl::AesBlockSize;

    // Extract the components of the original message.
    const QByteArray mac = msg.mid(msg.size() - BSz, BSz);
    const QByteArray iv = msg.mid(msg.size() - 2*BSz, BSz);
    const QByteArray content = msg.left(msg.size() - 2*BSz);

    // We're going to modify the first block
    const QByteArray firstBlock = content.left(BSz);
    const QByteArray theRest = content.mid(BSz);

    // Replace 'Alice' with an unknown victim.
    const QByteArray modFirst = QByteArray(firstBlock).replace("Alice","Victi");

    // Get the bit differences
    const QByteArray diff = qossl::xorByteArray(firstBlock,modFirst);

    // Apply same change to the IV => this will mean the total change is
    // transparent to the encryption, and hence the mac is unchanged.
    const QByteArray modIv = qossl::xorByteArray(iv, diff);

    // Recompose the message.
    const QByteArray attackMsg = modFirst + theRest + modIv + mac;

    // Prove the server accepts it.
    BankingServer server;
    QVERIFY(server.doTransaction(attackMsg));
}



