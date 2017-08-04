#include "testSet4.h"

#include <utils.h>

#include <QByteArray>
#include <QDebug>
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

