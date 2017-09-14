#include "testSet7_52.h"

#include <utils.h>

#include <QDebug>
#include <QTest>

#include "test.h"

JDS_ADD_TEST(TestSet7_52)

namespace {
    const quint16 H0 = 0x3141;

    // f
    class MdHash16 {
    public:
        static quint16 hash(const QByteArray & data, quint16 h0 = H0)
        {
            const int AesBlockSize = qossl::AesBlockSize;
            QByteArray padKey = QByteArray(AesBlockSize, (char)0);

            quint16 h = h0;  // Fixed initial value: Digits of Pi.

            for (int i = 0; i < data.size(); i += AesBlockSize)
            {
                padKey[0] = (char)( h &0xFF);
                padKey[1] = (char)((h >> 8)&0xFF);
                QByteArray nextBlock = data.mid(i, AesBlockSize);

                if (nextBlock.size() < AesBlockSize) {
                    // Only last block. Pad with zero.
                    nextBlock += QByteArray(AesBlockSize- nextBlock.size(), (char)0);
                }

                QByteArray block = qossl::aesEcbEncrypt(nextBlock, padKey);

                h = (unsigned)(unsigned char)(block.at(0))
                        | ((unsigned)(unsigned char)(block.at(1)) << 8);

            }

            return h;
        }
        private:
    };


    // g : 24-bit version.
    class MdHash24 {
    public:
        static quint32 hash(const QByteArray & data, quint32 h0 = 0x314159)
        {
            const int AesBlockSize = qossl::AesBlockSize;
            QByteArray padKey = QByteArray(AesBlockSize, (char)0);

            quint32 h = h0;  // Fixed initial value: Digits of Pi.

            for (int i = 0; i < data.size(); i += AesBlockSize)
            {
                padKey[0] = (char)( h &0xFF);
                padKey[1] = (char)((h >> 8)&0xFF);
                padKey[2] = (char)((h >>16)&0xFF);
                QByteArray nextBlock = data.mid(i, AesBlockSize);

                if (nextBlock.size() < AesBlockSize) {
                    // Only last block. Pad with zero.
                    nextBlock += QByteArray(AesBlockSize - nextBlock.size(), (char)0);
                }

                QByteArray block = qossl::aesEcbEncrypt(nextBlock, padKey);
                h = (unsigned)(unsigned char)(block.at(0))
                        | ((unsigned)(unsigned char)(block.at(1)) << 8)
                        | ((unsigned)(unsigned char)(block.at(2)) << 16);
            }

            return h;
        }
        private:
    };

    class CollisionFinder {

    public:
        CollisionFinder() : m_cfCount(0)
        {}

    struct Collision {
        Collision() {}
        Collision( quint16 hi, quint16 ho, const QByteArray & col1,const QByteArray & col2 ):
            hIn(hi),
            hOut(ho),
            c1(col1),
            c2(col2)
        {}

        quint16 hIn;
        quint16 hOut;
        QByteArray c1;
        QByteArray c2;
    };

    Collision findCollision(const quint16 hIn)
    {
        ++m_cfCount;

        QHash< quint16 ,QByteArray > tested;
        while(true) {
            QByteArray sample = qossl::randomBytes(qossl::AesBlockSize);

            quint16 hOut = MdHash16::hash(sample,hIn);
            if (tested.contains(hOut)) {
                if (tested.value(hOut) != sample) {
                    return Collision(hIn, hOut, tested.value(hOut), sample );
                }
            } else {
                tested[hOut].append(sample);
            }
        }
    }

    void find2nCollisions(int n)
    {
        quint16 h;
        if (m_collisions.isEmpty()) {
            h = H0;
        } else {
            h = m_collisions.back().hOut;
        }

        for (int i=0; i<n; ++i) {
            Collision nextC = findCollision(h);
            m_collisions.append(nextC);
            h = nextC.hOut;
            qDebug() << "Collision" << nextC.hIn << nextC.hOut << nextC.c1.toHex() << nextC.c2.toHex();
        }
        return;
    }

    quint16 hOut(int nMax = -1) const {
        if (m_collisions.isEmpty()) {
            return H0;
        }
        if (nMax == -1) {
            nMax = m_collisions.size() - 1;
        } else {
            nMax = std::min(nMax, m_collisions.size()-1);
        }
        return m_collisions.at(nMax).hOut;
    }

    int nMax() const { return m_collisions.size(); }

    QByteArray makeCollision(unsigned int n, int nMax = -1) const
    {
        QByteArray total;
        if (nMax == -1) {
            nMax = m_collisions.size();
        } else {
            nMax = std::min(nMax, m_collisions.size());
        }

        for (int i=0; i<nMax; ++i) {
            if ((n & (1<<i)) == 0) {
                total += m_collisions.at(i).c1;
            } else {
                total += m_collisions.at(i).c2;
            }
        }
        return total;
    }

    unsigned int cfCount() const { return m_cfCount; }
    private:
            QList<Collision> m_collisions;
            unsigned int m_cfCount; // number of calls
    };

}

void TestSet7_52::testChallenge52()
{
    CollisionFinder cf;

    unsigned int n = 4;
    cf.find2nCollisions(n);

    // print all 2^4 collisions.
    for (unsigned int i=0; i< (1<<n); ++i)
    {
        QByteArray data = cf.makeCollision(i);
        quint16 h = MdHash16::hash(data);
        QCOMPARE(h, cf.hOut());
    }

    // Keep increasing the number of messages in the pool until we hit a collision.
    bool haveCollision =false;
    while(!haveCollision && (n < 24)) {

        // Find more 2^4 times more collisions.
        cf.find2nCollisions(4);
        QHash < quint32, unsigned int > gHashes;

        n = cf.nMax();
        qDebug() << n;

        // See if there's a match in g.
        for (unsigned int i=0; i< (1<<n); ++i)
        {
            QByteArray data = cf.makeCollision(i);
            quint32 h = MdHash24::hash(data);
            if (gHashes.contains(h)) {
                qDebug() << "Collision in g found";
                haveCollision = true;

                QByteArray g1 = cf.makeCollision(gHashes.value(h));
                QByteArray g2 = data;
                qDebug() << "g1:" << g1.toHex();
                qDebug() << "g2:" << g2.toHex();

                // Confirm it collides for both functions:
                QCOMPARE(MdHash24::hash(g1), MdHash24::hash(g2));
                QCOMPARE(MdHash16::hash(g1), MdHash16::hash(g2));
                break;
            }
            gHashes[h] = i;
        }
    }

    QVERIFY(haveCollision);

    qDebug() << "Collision function called: " << cf.cfCount() << "times";
}
