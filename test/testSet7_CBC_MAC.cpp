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

namespace {

struct Recipient{
    Recipient(){}
    Recipient(const QByteArray & name_, unsigned int amount_) : amount(amount_), name(name_) {}

    unsigned int amount;
    QByteArray name;
};

// V2: Fixed IV
class BankingServer2 {
public:
    BankingServer2() :
        m_key("yellow submarine"),
        m_iv(QByteArray(qossl::AesBlockSize,0))
    {}

    // Parse and perform message.
    // Message of form "message || MAC"
    bool doTransaction(const QByteArray & message) {
        // Need mac or it's invalid.
        if (message.size() < qossl::AesBlockSize) {
            return false;
        }
        const QByteArray mac = message.mid(message.size() - qossl::AesBlockSize, qossl::AesBlockSize);
        const QByteArray content = message.left(message.size() - qossl::AesBlockSize);

        const QByteArray expectedMac = cbcMac(content, m_key, m_iv);
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
    const QByteArray m_iv;     // Private IV
};

class BankingClient2 {
public:
    BankingClient2(const QByteArray & user) :
        m_key("yellow submarine"),
        m_iv(QByteArray(qossl::AesBlockSize,0)),
        m_userId(user)
    {}

    QByteArray createMessage(const QList<Recipient>& recipientList) const
    {
        QByteArrayList recipStrings;
        foreach (const Recipient & it, recipientList) {
            recipStrings.append(it.name + ":" + QByteArray::number(it.amount));
        }
        const QByteArray data = "from=" + m_userId + "&tx_list=" + recipStrings.join(';');

        const QByteArray iv = qossl::randomBytes(qossl::AesBlockSize);
        const QByteArray mac = cbcMac(data,m_key,m_iv);
        return data + mac;
    }

private:
    const QByteArray m_key;     // Private Key
    const QByteArray m_iv;     // Private IV
    const QByteArray m_userId;
};
}


void TestSet7_CBC_MAC::testChallenge49_Part2()
{
    const BankingClient2 client("Alice");
    const QList< Recipient > recips = { Recipient("Bob",100) , Recipient("Charles", 500) };
    const QByteArray msg = client.createMessage(recips);

    BankingServer2 server;
    QVERIFY(server.doTransaction(msg));

    const int BSz = qossl::AesBlockSize;

    // Extract the components of the original message.
    const QByteArray mac = msg.mid(msg.size() - BSz, BSz);
    const QByteArray content = msg.left(msg.size() - BSz);

    const BankingClient2 clientH("Hacker");

    const QList< Recipient > fakelist = { Recipient("Boberrybob",1) , Recipient("AHacker", 1000000) };
    const QByteArray msg1 = clientH.createMessage( fakelist );

    // Block alignment: The target starts a new block.
    // 0123456789abcdef0123456789abcdef
    // from=Hacker&tx_list=Boberrybob:1;AHacker:1000000

    // (iv xor b1)   -----
    // Want to modify first block (b0) to give (b0')
    // (Mac xor b0')  = (iv0 xor b0).  Then the next encryption will take the same value.
    // So b0' = iv0 xor b0 xor Mac
    // The iv0 is zero, so can be dropped.
    // There'll be some garbage in the stream, but we can tolerate that if the server will.
    const QByteArray firstBlock = msg1.left(BSz);
    const QByteArray twister = qossl::xorByteArray(firstBlock, mac);

    // Recompose the message with the glue and length extension.
    const QByteArray restOfmsg1 = msg1.mid(BSz);
    const QByteArray attackMsg = qossl::pkcs7Pad(content,BSz) + twister + restOfmsg1;

    // Prove the server accepts it.
    QVERIFY(server.doTransaction(attackMsg));

    // How would you modify the protocol to prevent this?
    // By including a message length in the message.
    // By pre-pending the mac instead of appending.
}


namespace {
bool isPrintableAscii(const QByteArray & str)
{
    for (int j=0;j<str.size(); ++j) {
        unsigned char ch = (unsigned char)str.at(j);
        if ((ch > 126) || (ch == 0)){
            return false;
        }
    }

    return true;
}

}
void TestSet7_CBC_MAC::testChallenge50()
{
    const QByteArray test1 = "alert('MZA who was that?');\n";
    const QByteArray key = "YELLOW SUBMARINE";
    const QByteArray iv0 = QByteArray(qossl::AesBlockSize,0);

    const QByteArray actual = cbcMac(test1,key,iv0);
    const QByteArray expected = QByteArray::fromHex("296b8d7cb78a243dda4d0a61d33bbdd1");
    QCOMPARE(actual.toHex(), expected.toHex());

    QByteArray newCode = "alert('Ayo, the Wu is back!');\n";
    // Objective: add padding to give a the same hash.
    // This is AES, and we know the key, so we can do forward and reverse operations.
    // Each AES block is c = AES_ECB(prev xor block); prev = c;

    const int BSz = qossl::AesBlockSize;

    newCode += "/*"; // Block comment start to keep browser happy
    // Resize to whole blocks.
    if ((newCode.size() % BSz) != 0) {
        newCode += QByteArray(BSz - (newCode.size() % BSz), 'a');
    }

    // This is what (prev xor block) should be, in order to recover the hash.
    const QByteArray lastBlock = qossl::aesEcbDecrypt(expected,key);

    QByteArray desired = QByteArray(BSz,'a');
    desired[desired.size() - 1] = 1;  // valid padding.
    desired[desired.size() - 2] = '\n';  // Ends in Ends */, new line.
    desired[desired.size() - 3] = '/';
    desired[desired.size() - 4] = '*';

    QByteArray modLast;
    for (int i=0; i<1000000; ++i) {
        if (i%8096 == 0) {
            qDebug() << i;
        }

        // A counter, for forcing different glue bytes.
        const QByteArray numStr = QByteArray::number(i);
        for (int j=0; j<numStr.size(); ++j) {
            desired[j] = numStr.at(j);
        }

        // Find what prevC should be such that prev xor desired => lastBlock.
        const QByteArray prevC = qossl::aesEcbDecrypt(qossl::xorByteArray(desired,lastBlock),key);

        // This is the actual value of prev.
        const QByteArray cbc1 = qossl::aesCbcEncrypt(newCode,key,iv0).right(BSz);

        // So we need a glue block equal to:
        modLast = qossl::xorByteArray(prevC, cbc1);

        // Check if it's going to be valid UTF-8.
        if (isPrintableAscii(modLast)) {
            break;
        }
    }
    // We could check this and repeat, changing the padding slightly if it contains 'bad' characters.
    newCode += modLast;  // Glue 1
    newCode += desired;  // Glue 2

    newCode.resize(newCode.size() -1); // Drop padding bytes.
    //qDebug() << qossl::aesEcbEncrypt(qossl::xorByteArray(cbc1,modLast),key).toHex();
    qDebug() << newCode;

    // Write file
    if (false) {
        QFile op("/tmp/op.js");
        op.open(QFile::WriteOnly);
        op.write(newCode);
        op.close();
    }

    QCOMPARE(cbcMac(newCode,key,iv0).toHex(),expected.toHex());
}


