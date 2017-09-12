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


    QByteArray encryptCBC(const QByteArray & message)
    {
        const QByteArray iv = qossl::randomAesKey();
        const QByteArray key = qossl::randomAesKey();
        const QByteArray padded = qossl::pkcs7Pad(message,qossl::AesBlockSize);

        return qossl::aesCbcEncrypt(padded,key,iv);
    }

    int oracleCBC(const QByteArray & message)
    {
        return encryptCBC(compress(format_request(message))).length();
    }

    const char base64Charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                 "abcdefghijklmnopqrstuvwxyz"
                                 "0123456789+/=\r\n";

    char estimateNext(const QByteArray & payloadStart) {
        char cBest = 0;
        int minF = 999999;

        // First test with 1 additional character.
        QByteArray smallest;
        for (int i1=0; i1<67; ++i1) {
            const char c1 = base64Charset[i1];
            const int testV = oracle( payloadStart + c1 );
            if (testV < minF) {
                minF = testV;
                smallest.clear();
                smallest += c1;
            } else if (testV == minF) {
                smallest += c1;
            }
        }
        if (smallest.size() == 1) {
            return smallest.at(0);
        }

        // The minimum is not unique. Try two characters.
        minF = 999999;
        for (int i1=0; i1<smallest.length(); ++i1) {
            const char c1 = smallest.at(i1);

            for (int i2=0; i2<64; ++i2) {
                const char c2 = base64Charset[i2];

                const int testV = oracle( payloadStart + c1 + c2 );
                if (testV < minF) {
                    minF = testV;
                    cBest = c1;
                }
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


namespace {

// Block cipher version.
char estimateNextCbc(const QByteArray & payloadStart) {

    char cBest = 0;
    while (true) {
        cBest = 0;
        // 1. Add randomness until the returned size goes up by one block -> so we're working at
        //  a block boundary.
        QByteArray padBlock = qossl::randomBytes(8).toBase64();
        const int sz0 = oracleCBC(padBlock + payloadStart);
        int sz1;
        while (true) {
            padBlock += base64Charset[ qossl::randomUInt() % 64 ];
            sz1 = oracleCBC(padBlock + payloadStart);
            if (sz1 != sz0) {
                padBlock = padBlock.left(padBlock.size() - 1);
                break;
            }
        }

        int minF = 999999;

        QByteArray paddedStart = padBlock + payloadStart;
        // First test with 1 additional character.
        QByteArray smallest;
        for (int i1=0; i1<67; ++i1) {
            const char c1 = base64Charset[i1];
            const int testV = oracleCBC( paddedStart + c1 );
            if (testV < minF) {
                minF = testV;
                smallest.clear();
                smallest += c1;
            } else if (testV == minF) {
                smallest += c1;
            }
        }

        if (smallest.size() == 1) {
            return smallest.at(0);
        }

        //qDebug() << "Smallest sz" << smallest.size() << minF << sz0 << sz1;
        // The minimum is not unique. Try two characters.
        // Reduce padding.
        paddedStart = padBlock + payloadStart;
        if (minF == sz1) {
            paddedStart = padBlock.left(padBlock.size() - 1) + payloadStart;
        }

        int numMin = 0;
        for (int i1=0; i1<smallest.length(); ++i1) {
            const char c1 = smallest.at(i1);

            for (int i2=0; i2<64; ++i2) {
                const char c2 = base64Charset[i2];

                const int testV = oracleCBC( paddedStart + c1 + c2 );
                if (testV < minF) {
                    minF = testV;
                    cBest = c1;
                    numMin = 1;
                } else if(testV == minF) {
                    ++numMin;
                }
            }
        }

        // Special cases for the end
        const int numCouplets = 3;
        const char * eolCouplets[numCouplets] = { "=\r" , "==", "\r\n" };
        for (int i=0; i<numCouplets;++i) {
            int testV = oracleCBC( paddedStart + eolCouplets[i] );
            if (testV < minF) {
                minF = testV;
                cBest = eolCouplets[i][0];
                numMin = 1;
            } else if(testV == minF) {
                ++numMin;
            }
        }

        if (numMin > 1) {
            if (minF == sz1) {
                //qDebug() << "Loopin--" << padBlock;
            } else if (minF == sz0) {
                //qDebug() << "Loopin++" << padBlock;
            } else {
                qDebug() << numMin << minF << sz0 << sz1;
                break;
            }
            continue;
        }
        //qDebug() << "Found" << cBest;
        break;
    }

    return cBest;

}

} // namespace

void TestSet7_51::testChallenge51_cbc()
{
    const QByteArray payloadStart = "sessionid=";

    QByteArray payload = payloadStart;

    for (int i=0; i<64; ++i) {

        char cNext = estimateNextCbc(payload);
        char cNext2 = estimateNextCbc(payload);
        // Best of 3... needed to keep the error rate down.
        if (cNext != cNext2) {
            char cNext3 = estimateNextCbc(payload);
            if (cNext2 == cNext3){
                cNext = cNext2;
            }
        }
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
