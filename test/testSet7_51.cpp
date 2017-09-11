#include "testSet7_51.h"

#include <utils.h>

#include <QDebug>
#include <QTest>

#include "test.h"

JDS_ADD_TEST(TestSet7_51)

namespace {
    QByteArray format_request(const QByteArray & p)
    {
        QByteArray message =
            "POST / HTTP/1.1\r\n"
            "Host: hapless.com\r\n"
            "Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=\r\n";
        message += "Content-Length: " + QByteArray::number(p.size()) + "\r\n\r\n";
        message += p;
        return message;
    }

    QByteArray compress(const QByteArray & message)
    {
        return qCompress(message); // zlib.
    }

    QByteArray encrypt(const QByteArray & message)
    {
        const quint64 nonce = qossl::randomUInt64();
        const QByteArray key = qossl::randomAesKey();
        return qossl::aesCtrEncrypt(message,key,nonce,0);
    }

    int oracle(const QByteArray & message)
    {
        return encrypt(compress(format_request(message))).length();
    }

    const char base64Charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                 "abcdefghijklmnopqrstuvwxyz"
                                 "0123456789+/=";

    char estimateNext(const QByteArray & payloadStart) {
        char cBest = 0;
        int minF = 999999;

        for (int i=0; i<64*64; ++i) {
            char c1 = base64Charset[i % 64];
            char c2 = base64Charset[i / 64];

            int testV = oracle( payloadStart + c1 + c2 );
            if (testV < minF) {
                minF = testV;
                cBest = c1;
            }
        }

        // Special cases for the end
        const int numCouplets = 3;
        const char * eolCouplets[numCouplets] = { "=\r" , "==", "\r\n" };
        for (int i=0; i<numCouplets;++i) {
            int testV = oracle( payloadStart + eolCouplets[i] );
            if (testV < minF) {
                minF = testV;
                cBest = eolCouplets[i][0];
            }
        }

        return cBest;
    }
}

void TestSet7_51::testChallenge51()
{
    const QByteArray payloadStart = "sessionid=";


    QByteArray payload = payloadStart;

    for (int i=0; i<64; ++i) {

        char cNext = estimateNext(payload);
        if (cNext == '\r') {
            break;
        }
        payload += cNext;
    }

    const QByteArray actual = payload.mid(payloadStart.size());
    qDebug() << "Recovered sessionid:" << actual;

    const QByteArray expected = "TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=";
    QCOMPARE(actual, expected);
}
