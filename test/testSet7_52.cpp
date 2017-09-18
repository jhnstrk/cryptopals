#include "testSet7_52.h"

#include <bitsnbytes.h>
#include <utils.h>

#include <QDebug>
#include <QTest>

#include "test.h"

JDS_ADD_TEST(TestSet7_52)

namespace {
    QByteArray H0() {
        QByteArray ret;
        ret.resize(2);
        ret[0] = (char)0x31;
        ret[1] = (char)0x41;
        return ret;
    }

    class MdHashBase {
    protected:
        MdHashBase() : m_count(0) {}
        virtual ~MdHashBase() {}

        static const int BlockSizeBytes = qossl::AesBlockSize;

        QByteArray finalize()
        {
            m_buffer.append((char)0x80);
            if (m_buffer.size() <= (BlockSizeBytes - 8) ) {
                m_buffer.append( QByteArray((BlockSizeBytes - 8) - m_buffer.size(),'\0'));
            } else {
                m_buffer.append( QByteArray(BlockSizeBytes - m_buffer.size(),'\0'));
                this->addBlock(m_buffer,0);
                m_buffer = QByteArray((BlockSizeBytes - 8),'\0');
            }

            // Message length in bits
            m_buffer.append( qossl::uint64Le(m_count * CHAR_BIT) );

            this->addBlock(m_buffer,0);

            return m_state;
        }

        void addData(const QByteArray & data)
        {
            m_count += data.size();

            // less then a block
            if (m_buffer.size() + data.size() < BlockSizeBytes) {
                m_buffer.append(data);
                return;
            }

            int dataIndex = 0;
            if (!m_buffer.isEmpty()) {
                // fill buffer
                dataIndex = BlockSizeBytes - m_buffer.size();
                m_buffer.append(data.mid(0,dataIndex));
                this->addBlock(m_buffer,0);
            }

            int end = dataIndex + BlockSizeBytes;
            while (end <= data.size()) {
                this->addBlock(data, dataIndex);
                dataIndex = end;
                end += BlockSizeBytes;
            }

            m_buffer = data.mid(dataIndex);
        }

        virtual void addBlock(const QByteArray &data, int offset) = 0;
    protected:
        QByteArray m_state;
        int m_count;
    private:
        QByteArray m_buffer;
    };

    // f
    class MdHash16 : public MdHashBase {
    public:
        MdHash16() {
            this->reset();
        }

        void reset() {
            m_state = H0();
            m_count = 0;
        }

        static QByteArray hash(const QByteArray & data)
        {
            MdHash16 hasher;
            hasher.addData(data);
            return hasher.finalize();
        }

        void addBlock(const QByteArray &data, int offset) Q_DECL_OVERRIDE
        {
            this->m_state = MdHash16::iteration(data.mid(offset,BlockSizeBytes), this->m_state);
        }

        static QByteArray iteration(const QByteArray & block, const QByteArray & hIn)
        {
            QByteArray padKey = QByteArray(BlockSizeBytes, (char)0);
            padKey[0] = hIn.at(0);
            padKey[1] = hIn.at(1);

            QByteArray eblock = qossl::aesEcbEncrypt(block, padKey);
            eblock.resize(2);
            return eblock;
        }

    };


    // g : 24-bit version.
    class MdHash24 : public MdHashBase {
    public:
        MdHash24() {
            this->reset();
        }

        void reset() {
            m_state.resize(3);
            m_state[0] = (char)0x31;
            m_state[1] = (char)0x41;
            m_state[2] = (char)0x59;  // Digits of Pi.
            m_count = 0;
        }

        static QByteArray hash(const QByteArray & data)
        {
            MdHash24 hasher;
            hasher.addData(data);
            return hasher.finalize();
        }

        void addBlock(const QByteArray &data, int offset) Q_DECL_OVERRIDE
        {
            this->m_state = MdHash16::iteration( data.mid(offset,BlockSizeBytes), this->m_state);
        }

        static QByteArray iteration(const QByteArray & block, const QByteArray & hIn)
        {
            QByteArray padKey = QByteArray(BlockSizeBytes, (char)0);
            padKey[0] = hIn.at(0);
            padKey[1] = hIn.at(1);
            padKey[2] = hIn.at(2);

            QByteArray eblock = qossl::aesEcbEncrypt(block, padKey);
            eblock.resize(3);
            return eblock;
        }
        private:
    };

    class CollisionFinder {

    public:
        CollisionFinder() : m_cfCount(0)
        {}

    struct Collision {
        Collision() {}
        Collision( const QByteArray& hi, const QByteArray & ho,
                   const QByteArray & col1,const QByteArray & col2 ):
            hIn(hi), // Input state
            hOut(ho), // output state
            c1(col1),
            c2(col2)
        {}

        QByteArray hIn;
        QByteArray hOut;
        QByteArray c1;
        QByteArray c2;
    };

    Collision findCollision(const QByteArray& hIn)
    {
        ++m_cfCount;

        QHash< QByteArray ,QByteArray > tested;
        while(true) {
            QByteArray sample = qossl::randomBytes(qossl::AesBlockSize);

            QByteArray hOut = MdHash16::iteration(sample,hIn);
            if (tested.contains(hOut)) {
                if (tested.value(hOut) != sample) {
                    return Collision(hIn, hOut, tested.value(hOut), sample );
                }
            } else {
                tested[hOut] = sample;
            }
        }
    }

    void find2nCollisions(int n)
    {
        QByteArray h;
        if (m_collisions.isEmpty()) {
            h = H0();
        } else {
            h = m_collisions.back().hOut;
        }

        for (int i=0; i<n; ++i) {
            Collision nextC = findCollision(h);
            m_collisions.append(nextC);
            h = nextC.hOut;
            qDebug() << "Collision" << nextC.hIn.toHex() << nextC.hOut.toHex()
                     << nextC.c1.toHex() << nextC.c2.toHex();
        }
        return;
    }

    QByteArray hOut(int nMax = -1) const {
        if (m_collisions.isEmpty()) {
            return H0();
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
    QByteArray cValue;
    for (unsigned int i=0; i< (1<<n); ++i)
    {
        const QByteArray data = cf.makeCollision(i);
        const QByteArray h = MdHash16::hash(data);
        qDebug() << i << h.toHex();
        if (i == 0) {
            cValue = h;
        } else {
            QCOMPARE(h, cValue);  // Ensure collision, including padding matches.
        }
    }

    qDebug() << "Found 2^4 collisions";

    // Keep increasing the number of messages in the pool until we hit a collision.
    bool haveCollision =false;
    while(!haveCollision && (n < 24)) {

        // Find more 2^4 times more collisions.
        cf.find2nCollisions(4);
        QHash < QByteArray, unsigned int > gHashes;

        n = cf.nMax();

        // See if there's a match in g.
        for (unsigned int i=0; i< (1<<n); ++i)
        {
            QByteArray data = cf.makeCollision(i);
            QByteArray h = MdHash24::hash(data);
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
