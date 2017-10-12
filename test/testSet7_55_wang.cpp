#include "testSet7_55_wang.h"

#include <bitsnbytes.h>
#include <md4.h>
#include <utils.h>

#include <QDebug>
#include <QTest>

#include "test.h"

JDS_ADD_TEST(TestSet7_55_wang)

namespace {

    class HackWord {
    public:
        class BitRef {
        public:
            BitRef(quint32 & w, int b) : m_w(w), m_b(b) {}

            BitRef & operator=(const BitRef & other) {
                return this->operator =((bool)other);
            }

            BitRef & operator=(const int v) {
                if ((v != 0) && (v != 1)) {
                    qWarning() << "Invalid value for bit" << v;
                }
                return this->operator =(v != 0);
            }

            BitRef & operator=(const bool v) {
                if (v) {
                    m_w |= ( 1 << m_b );
                } else {
                    m_w &= (~quint32(1 << m_b));
                }
                return *this;
            }

            operator int() const
            {
                return ((m_w >> m_b) & 1);
            }
        private:
            quint32 & m_w;
            const int m_b;   // Bit pos, ZERO based.
        };

        HackWord(quint32 v = 0):m_w(v) {}
        HackWord(const HackWord & other):m_w(other.m_w) {}

            // Bit number starts from 1
        BitRef operator[](int bitpos){ return BitRef(m_w, bitpos - 1); }
        bool operator[](int bitpos) const{ return ((m_w >> (bitpos - 1)) & 1) != 0; }

        operator quint32 () const { return m_w; }

        HackWord & operator =(quint32 v) { m_w = v; return *this;}
        HackWord & operator =(const HackWord & other) { m_w = other.m_w; return *this;}
    private:
        quint32 m_w;
    };

    // F(X,Y,Z) = XY v not(X) Z
    inline quint32 F(const quint32 x, const quint32 y, const quint32 z){
        return (x & y) | ( (~x) & z);
    }

    //G(X,Y,Z) = XY v XZ v YZ
    inline quint32 G(const quint32 x, const quint32 y, const quint32 z){
        return (x & y) | (x & z) | (y & z);
    }

    //H(X,Y,Z) = X xor Y xor Z
    inline quint32 H(const quint32 x, const quint32 y, const quint32 z){
        return x ^ y ^ z;
    }

    // Let [abcd k s] denote the operation
    //a = (a + F(b,c,d) + X[k]) <<< s.
    inline quint32 FF(const quint32 a, const quint32 b, const quint32 c, const quint32 d,
                const quint32 x_k, const unsigned int s)
    {
        return qossl::leftrotate((a + F(b,c,d) + x_k),s);
    }

    // Round2: Let [abcd k s] denote the operation
    // a = (a + G(b,c,d) + X[k] + 5A827999) <<< s.
    inline quint32 GG(const quint32 a, const quint32 b, const quint32 c, const quint32 d,
                const quint32 x_k, const unsigned int s)
    {
        return qossl::leftrotate((a + G(b,c,d) + x_k + 0x5A827999u),s);
    }

    //Round3: Let [abcd k s] denote the operation
    // a = (a + H(b,c,d) + X[k] + 6ED9EBA1) <<< s.
    inline quint32 HH(const quint32 a, const quint32 b, const quint32 c, const quint32 d,
                const quint32 x_k, const unsigned int s)
    {
        return qossl::leftrotate((a + H(b,c,d) + x_k + 0x6ED9EBA1u),s);
    }

    // Recover x_k given output:
    // y = FF(a,b,c,d,x_k,s);
    // x_k = invFF(a,b,c,d,y,s);
    inline quint32 invFF(const quint32 a, const quint32 b, const quint32 c, const quint32 d,
                const quint32 y, const unsigned int s)
    {
        return qossl::rightrotate(y,s) - a - F(b,c,d);
    }

    const   quint32  A0 = 0x67452301u;
    const   quint32  B0 = 0xEFCDAB89u;
    const   quint32  C0 = 0x98BADCFEu;
    const   quint32  D0 = 0x10325476u;

    QVector<quint32> fromBytes(const QByteArray & arr)
    {
        QVector<quint32> ret;
        if (arr.isEmpty()) {
            return ret;
        }

        const int n_w = (arr.size() / sizeof(quint32));
        const int n_p = (arr.size() % sizeof(quint32));
        const int n = n_w + (n_p == 0 ? 0 : 1);
        ret.reserve(n);

        const unsigned char * p = reinterpret_cast<const unsigned char *>(arr.constData());
        for (int i=0; i<n_w; ++i) {
            ret.push_back(qossl::uint32_from_le(p + i*sizeof(quint32)));
        }

        if (n_p != 0) {
            unsigned char ppad[sizeof(quint32)] = {0};
            for (int i=0; i<n_p; ++i) {
                ppad[i] = arr.at(i + n_w*sizeof(quint32));
            }
            ret.push_back(qossl::uint32_from_le(ppad));
        }

        return ret;
    }

    QByteArray toBytes(const QVector<quint32> & arr) {
        QByteArray ret;
        ret.reserve(arr.size() * sizeof(quint32));
        for (quint32 it : arr) {
            ret.push_back(qossl::uint32Le(it));
        }
        return ret;
    }


    QVector<quint32> randomBlock()
    {
        const QByteArray bytes = qossl::randomBytes(qossl::Md4::BlockSizeBytes);
        return fromBytes(bytes);
    }
}

namespace Wang {

    QByteArray WordsToBytes(const QByteArray & src){
        QByteArray ret = QByteArray::fromHex(src);
        for (int i=0; i<ret.size(); i+=4) {
            std::reverse(ret.begin()+i, ret.begin()+i+4);
        }
        return ret;
    }

    // These seem to be the values that work, but it's a mess.
    //
    // It seems that the messages are written as a sequence of Words (i.e. big-endian 32-bit)
    // but the final hash is written as per the Md4 spec; as a sequence of bytes.
    // TODO: Verify what is meant in the paper by
    //     "H is the hash value with little-endian and no message padding, and H∗
    //        is the hash value with big-endian and message padding"
    //  => I can't see what is big-endian here.
    const QByteArray m1=WordsToBytes(
    "4d7a9c83 56cb927a b9d5a578 57a7a5ee de748a3c dcc366b3 b683a020 3b2a5d9f"
    "c69d71b3 f9e99198 d79f805e a63bb2e8 45dd8e31 97e31fe5 2794bf08 b9e8c3e9");
    const QByteArray m1dash=WordsToBytes(
                "4d7a9c83 d6cb927a 29d5a578 57a7a5ee de748a3c dcc366b3 b683a020 3b2a5d9f"
    "c69d71b3 f9e99198 d79f805e a63bb2e8 45dc8e31 97e31fe5 2794bf08 b9e8c3e9");
    const QByteArray h1=QByteArray::fromHex("5f5c1a0d 71b36046 1b5435da 9b0d807a");
    const QByteArray h1star=QByteArray::fromHex("4d7e6a1d efa93d2d de05b45d 864c429b");
    const QByteArray m2=WordsToBytes(
    "4d7a9c83 56cb927a b9d5a578 57a7a5ee de748a3c dcc366b3 b683a020 3b2a5d9f"
    "c69d71b3 f9e99198 d79f805e a63bb2e8 45dd8e31 97e31fe5 f713c240 a7b8cf69");
    const QByteArray m2dash=WordsToBytes(
    "4d7a9c83 d6cb927a 29d5a578 57a7a5ee de748a3c dcc366b3 b683a020 3b2a5d9f"
    "c69d71b3 f9e99198 d79f805e a63bb2e8 45dc8e31 97e31fe5 f713c240 a7b8cf69");
    const QByteArray h2=QByteArray::fromHex("e0f76122 c429c56c ebb5e256 b809793");
    const QByteArray h2star=QByteArray::fromHex("c6f3b3fe 1f4833e0 697340fb 214fb9ea");


}

class WangAttack {
    HackWord a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10;
    HackWord b0,b1,b2,b3,b4,b5,b6,b7,b8,b9,b10;
    HackWord c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10;
    HackWord d0,d1,d2,d3,d4,d5,d6,d7,d8,d9,d10;

public:
    WangAttack() : a0(A0),b0(B0),c0(C0),d0(D0) {}

    void modifyM(QVector<quint32> &m);

    void checkM(const QVector<quint32> &m);
protected:

    void applyRound1Corrections(QVector<quint32> & m);
    void applyRound2Corrections(QVector<quint32> & m);

    //! Return true if a change was made.
    bool applyTable1_a(QVector<quint32> & m, HackWord & w, const int i,  int desired);
    bool applyTable1_d(QVector<quint32> & m, HackWord & w, const int i,  int desired);
    bool applyTable2(  QVector<quint32> & m, HackWord & w, const int i,  bool desired);

};

void WangAttack::checkM(const QVector<quint32> &m)
{
    a1 = FF(a0,b0,c0,d0, m.at( 0),3);
    d1 = FF(d0,a1,b0,c0, m.at( 1),7);
    c1 = FF(c0,d1,a1,b0, m.at( 2),11);
    b1 = FF(b0,c1,d1,a1, m.at( 3),19);
    a2 = FF(a1,b1,c1,d1, m.at( 4),3);
    d2 = FF(d1,a2,b1,c1, m.at( 5),7);
    c2 = FF(c1,d2,a2,b1, m.at( 6),11);
    b2 = FF(b1,c2,d2,a2, m.at( 7),19);
    a3 = FF(a2,b2,c2,d2, m.at( 8),3);
    d3 = FF(d2,a3,b2,c2, m.at( 9),7);
    c3 = FF(c2,d3,a3,b2, m.at(10),11);
    b3 = FF(b2,c3,d3,a3, m.at(11),19);
    a4 = FF(a3,b3,c3,d3, m.at(12),3);
    d4 = FF(d3,a4,b3,c3, m.at(13),7);
    c4 = FF(c3,d4,a4,b3, m.at(14),11);
    b4 = FF(b3,c4,d4,a4, m.at(15),19);
    a5 = GG(a4,b4,c4,d4, m.at( 0),3);
    d5 = GG(d4,a5,b4,c4, m.at( 4),5);
    c5 = GG(c4,d5,a5,b4, m.at( 8),9);
    b5 = GG(b4,c5,d5,a5, m.at(12),13);
    a6 = GG(a5,b5,c5,d5, m.at( 1),3);
    d6 = GG(d5,a6,b5,c5, m.at( 5),5);
    c6 = GG(c5,d6,a6,b5, m.at( 9),9);
    b6 = GG(b5,c6,d6,a6, m.at(13),13);
    a7 = GG(a6,b6,c6,d6, m.at( 2),3);
    d7 = GG(d6,a7,b6,c6, m.at( 6),5);
    c7 = GG(c6,d7,a7,b6, m.at(10),9);
    b7 = GG(b6,c7,d7,a7, m.at(14),13);
    a8 = GG(a7,b7,c7,d7, m.at( 3),3);
    d8 = GG(d7,a8,b7,c7, m.at( 7),5);
    c8 = GG(c7,d8,a8,b7, m.at(11),9);
    b8 = GG(b7,c8,d8,a8, m.at(15),13);

    // Condition 1: a1[7] = b0[7]
    QCOMPARE((int)a1[7], (int)b0[7]);

    // Condition 2: d1,7 = 0, d1,8 = a1,8, d1,11 = a1,11
    QCOMPARE((int)d1[ 7], 0);
    QCOMPARE((int)d1[ 8], (int)a1[8]);
    QCOMPARE((int)d1[11], (int)a1[11]);

    // Condition 3: c1,7 = 1, c1,8 = 1, c1,11 = 0, c1,26 = d1,26
    QCOMPARE((int)c1[7], 1);
    QCOMPARE((int)c1[8], 1);
    QCOMPARE((int)c1[11], 0);
    QCOMPARE((int)c1[26], (int)d1[26]);

    // Condition 4: b1,7 = 1, b1,8 = 0, b1,11 = 0, b1,26 = 0
    QCOMPARE((int)b1[7], 1);
    QCOMPARE((int)b1[8], 0);
    QCOMPARE((int)b1[11], 0);
    QCOMPARE((int)b1[26], 0);

    // Condition 5: a2,8 = 1, a2,11 = 1, a2,26 = 0, a2,14 = b1,14
    QCOMPARE((int)a2[8], 1);
    QCOMPARE((int)a2[11], 1);
    QCOMPARE((int)a2[26], 0);
    QCOMPARE((int)a2[14], (int)b1[14]);

    // Condition 6: d2,14 = 0, d2,19 = a2,19, d2,20 = a2,20, d2,21 = a2,21, d2,22 = a2,22, d2,26 = 1
    QCOMPARE((int)d2[14], 0);
    QCOMPARE((int)d2[19], (int)a2[19]);
    QCOMPARE((int)d2[20], (int)a2[20]);
    QCOMPARE((int)d2[21], (int)a2[21]);
    QCOMPARE((int)a2[22], (int)a2[22]);
    QCOMPARE((int)d2[26], 1);

    // Condition 7: c2,13 = d2,13, c2,14 = 0, c2,15 = d2,15, c2,19 = 0, c2,20 = 0, c2,21 = 1, c2,22 = 0
    QCOMPARE((int)c2[13], (int)d2[13]);
    QCOMPARE((int)c2[14], (int)c2[15]);
    QCOMPARE((int)c2[19], 0);
    QCOMPARE((int)c2[20], 0);
    QCOMPARE((int)c2[21], 1);
    QCOMPARE((int)c2[22], 0);

    // Condition 8: b2,13 = 1, b2,14 = 1, b2,15 = 0, b2,17 = c2,17, b2,19 = 0,
    //   b2,20 = 0, b2,21 = 0,  b2,22 = 0
    QCOMPARE((int)b2[13], 1);
    QCOMPARE((int)b2[14], 1);
    QCOMPARE((int)b2[15], 0);
    QCOMPARE((int)b2[17], (int)c2[17]);
    QCOMPARE((int)b2[19], 0);

    // Condition 9: a3,13 = 1, a3,14 = 1, a3,15 = 1, a3,17 = 0, a3,19 = 0,
    //   a3,20 = 0, a3,21 = 0, a3,23 = b2,23 a3,22 = 1, a3,26 = b2,26
    QCOMPARE((int)a3[13], 1);
    QCOMPARE((int)a3[14], 1);
    QCOMPARE((int)a3[15], 1);
    QCOMPARE((int)a3[17], 0);
    QCOMPARE((int)a3[19], 0);
    QCOMPARE((int)a3[20], 0);
    QCOMPARE((int)a3[21], 0);
    QCOMPARE((int)a3[23], (int)b2[23]);
    QCOMPARE((int)a3[22], 1);
    QCOMPARE((int)a3[26], (int)b2[26]);

    // Condition 10: d3,13 = 1, d3,14 = 1, d3,15 = 1, d3,17 = 0, d3,20 = 0,
    //    d3,21 = 1, d3,22 = 1, d3,23 = 0, d3,26 = 1, d3,30 = a3,30
    QCOMPARE((int)d3[13], 1);
    QCOMPARE((int)d3[14], 1);
    QCOMPARE((int)d3[15], 1);
    QCOMPARE((int)d3[17], 0);
    QCOMPARE((int)d3[20], 0);
    QCOMPARE((int)d3[21], 1);
    QCOMPARE((int)d3[22], 1);
    QCOMPARE((int)d3[23], 0);
    QCOMPARE((int)d3[26], 1);
    QCOMPARE((int)d3[30], (int)a3[30]);

    // Condition 11: c3,17 = 1, c3,20 = 0, c3,21 = 0, c3,22 = 0, c3,23 = 0,
    //    c3,26 = 0, c3,30 = 1, c3,32 = d3,32
    QCOMPARE((int)c3[17], 1);
    QCOMPARE((int)c3[20], 0);
    QCOMPARE((int)c3[21], 0);
    QCOMPARE((int)c3[22], 0);
    QCOMPARE((int)c3[23], 0);
    QCOMPARE((int)c3[26], 0);
    QCOMPARE((int)c3[30], 1);
    QCOMPARE((int)c3[32], (int)d3[32]);

    // Condition 12: b3,20 = 0, b3,21 = 1, b3,22 = 1, b3,23 = c3,23, b3,26 = 1,
    //    b3,30 = 0, b3,32 = 0
    QCOMPARE((int)b3[20], 0);
    QCOMPARE((int)b3[21], 1);
    QCOMPARE((int)b3[22], 1);
    QCOMPARE((int)b3[23], (int)c3[23]);
    QCOMPARE((int)b3[26], 1);
    QCOMPARE((int)b3[30], 0);
    QCOMPARE((int)b3[32], 0);

    // Condition 13: a4,23 = 0, a4,26 = 0, a4,27 = b3,27, a4,29 = b3,29, a4,30 = 1, a4,32 = 0
    QCOMPARE((int)a4[23], 0);
    QCOMPARE((int)a4[26], 0);
    QCOMPARE((int)a4[27], (int)b3[27]);
    QCOMPARE((int)a4[29], (int)b3[29]);
    QCOMPARE((int)a4[30], 1);
    QCOMPARE((int)a4[32], 0);

    // Condition 14: d4,23 = 0, d4,26 = 0, d4,27 = 1, d4,29 = 1, d4,30 = 0, d4,32 = 1
    QCOMPARE((int)d4[23], 0);
    QCOMPARE((int)d4[26], 0);
    QCOMPARE((int)d4[27], 1);
    QCOMPARE((int)d4[29], 1);
    QCOMPARE((int)d4[30], 0);
    QCOMPARE((int)d4[32], 1);

    // Condition 15: c4,19 = d4,19, c4,23 = 1, c4,26 = 1, c4,27 = 0, c4,29 = 0, c4,30 = 0
    QCOMPARE((int)c4[19], (int)d4[19]);
    QCOMPARE((int)c4[23], 1);
    QCOMPARE((int)c4[26], 1);
    QCOMPARE((int)c4[27], 0);
    QCOMPARE((int)c4[29], 0);
    QCOMPARE((int)c4[30], 0);

    // Condition 16: b4,19 = 0, b4,26 = c4,26 = 1 (typo in paper?), b4,27 = 1, b4,29 = 1, b4,30 = 0
    QCOMPARE((int)b4[19], 0);
    QCOMPARE((int)b4[26], 1);
    QCOMPARE((int)b4[27], 1);
    QCOMPARE((int)b4[29], 1);
    QCOMPARE((int)b4[30], 0);

    // Round 2...
    // Condition 17: a5,19 = c4,19, a5,26 = 1, a5,27 = 0, a5,29 = 1, a5,32 = 1
    QCOMPARE((int)a5[19], (int)c4[19]);
    QCOMPARE((int)a5[26], 1);
    QCOMPARE((int)a5[27], 0);
    QCOMPARE((int)a5[29], 1);
    QCOMPARE((int)a5[32], 1);

    // Condition 18: d5,19 = a5,19, d5,26 = b4,26, d5,27 = b4,27, d5,29 = b4,29, d5,32 = b4,32
    QCOMPARE((int)d5[19], (int)a5[19]);
    QCOMPARE((int)d5[26], (int)b4[26]);
    QCOMPARE((int)d5[27], (int)b4[27]);
    QCOMPARE((int)d5[29], (int)b4[29]);
    QCOMPARE((int)d5[32], (int)b4[32]);

    // Condition 19: c5,26 = d5,26, c5,27 = d5,27, c5,29 = d5,29, c5,30 = d5,30, c5,32 = d5,32
    QCOMPARE((int)c5[26], (int)d5[26]);
    QCOMPARE((int)c5[27], (int)d5[27]);
    QCOMPARE((int)c5[29], (int)d5[29]);
    QCOMPARE((int)c5[30], (int)d5[30]);
    QCOMPARE((int)c5[32], (int)d5[32]);

    // Condition 20: b5,29 = c5,29, b5,30 = 1, b5,32 = 0
    QCOMPARE((int)b5[29], (int)c5[29]);
    QCOMPARE((int)b5[30], 1);
    QCOMPARE((int)b5[32], 0);

    // Condition 21: a6,29 = 1, a6,32 = 1
    QCOMPARE((int)a6[29], 1);
    QCOMPARE((int)a6[32], 1);

    // Condition 22: d6,29 = b5,29
    QCOMPARE((int)d6[29], (int)b5[29]);

    // Condition 23: c6,29 = d6,29, c6,30 = d6,30 + 1, c6,32 = d6,32 + 1
    QCOMPARE((int)c6[29], (int)d6[29]);
    QCOMPARE((bool)c6[30], !(bool)d6[30]);
    QCOMPARE((bool)c6[32], !(bool)d6[32]);
#if 0
    // Condition 24: b9,32 = 1
    QCOMPARE((int)b9[32], 1);

    // Condition 25: a10,32 = 1
    QCOMPARE((int)a10[32], 1);
#endif
}

void WangAttack::modifyM(QVector<quint32> &m)
{
    applyRound1Corrections(m);
    applyRound2Corrections(m);
    applyRound1Corrections(m);
    applyRound2Corrections(m);
    applyRound1Corrections(m);
    applyRound2Corrections(m);
    applyRound1Corrections(m);
}

void WangAttack::applyRound1Corrections(QVector<quint32> &m)
{
    // Condition 1: a1[7] = b0[7]
    a1 = FF(a0,b0,c0,d0, m.at(0),3);
    a1[7] = b0[7];

    // Fix m0
    //     a1 = lrot((a0 + F(b0,c0,d0) + m0),3);
    // =>  m0 = rrot(a1,3) - F(b0,c0,d0) - a0
    m[0] = invFF(a0,b0,c0,d0, a1,3);

    // Condition 2: d1,7 = 0, d1,8 = a1,8, d1,11 = a1,11
    d1 = FF(d0,a1,b0,c0, m.at(1),7);
    d1[ 7] = 0;
    d1[ 8] = a1[8];
    d1[11] = a1[11];
    m[1] = invFF(d0,a1,b0,c0, d1,7);

    // Condition 3: c1,7 = 1, c1,8 = 1, c1,11 = 0, c1,26 = d1,26
    c1 = FF(c0,d1,a1,b0, m.at(2),11);
    c1[7] = 1;
    c1[8] = 1;
    c1[11] = 0;
    c1[26] = d1[26];
    m[2] = invFF(c0,d1,a1,b0, c1,11);

    // Condition 4: b1,7 = 1, b1,8 = 0, b1,11 = 0, b1,26 = 0
    b1 = FF(b0,c1,d1,a1, m.at(3),19);
    b1[7] = 1;
    b1[8] = 0;
    b1[11] = 0;
    b1[26] = 0;
    m[3] = invFF(b0,c1,d1,a1, b1,19);

    // Condition 5: a2,8 = 1, a2,11 = 1, a2,26 = 0, a2,14 = b1,14
    a2 = FF(a1,b1,c1,d1, m.at(4),3);
    a2[8] = 1;
    a2[11] = 1;
    a2[26] = 0;
    a2[14] = b1[14];
    m[4] = invFF(a1,b1,c1,d1, a2,3);

    // Condition 6: d2,14 = 0, d2,19 = a2,19, d2,20 = a2,20, d2,21 = a2,21, d2,22 = a2,22, d2,26 = 1
    d2 = FF(d1,a2,b1,c1, m.at(5),7);
    d2[14] = 0;
    d2[19] = a2[19];
    d2[20] = a2[20];
    d2[21] = a2[21];
    a2[22] = a2[22];
    d2[26] = 1;
    m[5] = invFF(d1,a2,b1,c1, d2,7);

    // Condition 7: c2,13 = d2,13, c2,14 = 0, c2,15 = d2,15, c2,19 = 0, c2,20 = 0, c2,21 = 1, c2,22 = 0
    c2 = FF(c1,d2,a2,b1, m.at(6),11);
    c2[13] = d2[13];
    c2[14] = c2[15];
    c2[19] = 0;
    c2[20] = 0;
    c2[21] = 1;
    c2[22] = 0;
    m[6] = invFF(c1,d2,a2,b1, c2,11);

    // Condition 8: b2,13 = 1, b2,14 = 1, b2,15 = 0, b2,17 = c2,17, b2,19 = 0,
    //   b2,20 = 0, b2,21 = 0,  b2,22 = 0
    b2 = FF(b1,c2,d2,a2, m.at(7),19);
    b2[13] = 1;
    b2[14] = 1;
    b2[15] = 0;
    b2[17] = c2[17];
    b2[19] = 0;
    m[7] = invFF(b1,c2,d2,a2, b2,19);

    // Condition 9: a3,13 = 1, a3,14 = 1, a3,15 = 1, a3,17 = 0, a3,19 = 0,
    //   a3,20 = 0, a3,21 = 0, a3,23 = b2,23 a3,22 = 1, a3,26 = b2,26
    a3 = FF(a2,b2,c2,d2, m.at(8),3);
    a3[13] = 1;
    a3[14] = 1;
    a3[15] = 1;
    a3[17] = 0;
    a3[19] = 0;
    a3[20] = 0;
    a3[21] = 0;
    a3[23] = b2[23];
    a3[22] = 1;
    a3[26] = b2[26];
    m[8] = invFF(a2,b2,c2,d2, a3,3);

    // Condition 10: d3,13 = 1, d3,14 = 1, d3,15 = 1, d3,17 = 0, d3,20 = 0,
    //    d3,21 = 1, d3,22 = 1, d3,23 = 0, d3,26 = 1, d3,30 = a3,30
    d3 = FF(d2,a3,b2,c2, m.at(9),7);
    d3[13] = 1;
    d3[14] = 1;
    d3[15] = 1;
    d3[17] = 0;
    d3[20] = 0;
    d3[21] = 1;
    d3[22] = 1;
    d3[23] = 0;
    d3[26] = 1;
    d3[30] = a3[30];
    m[9] = invFF(d2,a3,b2,c2, d3,7);
    // Condition 11: c3,17 = 1, c3,20 = 0, c3,21 = 0, c3,22 = 0, c3,23 = 0,
    //    c3,26 = 0, c3,30 = 1, c3,32 = d3,32
    c3 = FF(c2,d3,a3,b2,m.at(10),11);
    c3[17] = 1;
    c3[20] = 0;
    c3[21] = 0;
    c3[22] = 0;
    c3[23] = 0;
    c3[26] = 0;
    c3[30] = 1;
    c3[32] = d3[32];
    m[10] = invFF(c2,d3,a3,b2,c3,11);

    // Condition 12: b3,20 = 0, b3,21 = 1, b3,22 = 1, b3,23 = c3,23, b3,26 = 1,
    //    b3,30 = 0, b3,32 = 0
    b3 = FF(b2,c3,d3,a3,m.at(11),19);
    b3[20] = 0;
    b3[21] = 1;
    b3[22] = 1;
    b3[23] = c3[23];
    b3[26] = 1;
    b3[30] = 0;
    b3[32] = 0;
    m[11] = invFF(b2,c3,d3,a3,b3,19);

    // Condition 13: a4,23 = 0, a4,26 = 0, a4,27 = b3,27, a4,29 = b3,29, a4,30 = 1, a4,32 = 0
    a4 = FF(a3,b3,c3,d3,m.at(12),3);
    a4[23] = 0;
    a4[26] = 0;
    a4[27] = b3[27];
    a4[29] = b3[29];
    a4[30] = 1;
    a4[32] = 0;
    m[12] = invFF(a3,b3,c3,d3,a4,3);

    // Condition 14: d4,23 = 0, d4,26 = 0, d4,27 = 1, d4,29 = 1, d4,30 = 0, d4,32 = 1
    d4 = FF(d3,a4,b3,c3,m.at(13),7);
    d4[23] = 0;
    d4[26] = 0;
    d4[27] = 1;
    d4[29] = 1;
    d4[30] = 0;
    d4[32] = 1;
    m[13] = invFF(d3,a4,b3,c3,d4,7);

    // Condition 15: c4,19 = d4,19, c4,23 = 1, c4,26 = 1, c4,27 = 0, c4,29 = 0, c4,30 = 0
    c4 = FF(c3,d4,a4,b3,m.at(14),11);
    c4[19] = d4[19];
    c4[23] = 1;
    c4[26] = 1;
    c4[27] = 0;
    c4[29] = 0;
    c4[30] = 0;
    m[14] = invFF(c3,d4,a4,b3,c4,11);

    // Condition 16: b4,19 = 0, b4,26 = c4,26 = 1 (typo in paper?), b4,27 = 1, b4,29 = 1, b4,30 = 0
    b4 = FF(b3,c4,d4,a4,m.at(15),19);
    b4[19] = 0;
    b4[26] = 1;
    b4[27] = 1;
    b4[29] = 1;
    b4[30] = 0;
    m[15] = invFF(b3,c4,d4,a4,b4,19);
}
void WangAttack::applyRound2Corrections(QVector<quint32> &m)
{
    // Round 2...
    // Condition 17: a5,19 = c4,19, a5,26 = 1, a5,27 = 0, a5,29 = 1, a5,32 = 1
    a5 = GG(a4,b4,c4,d4, m.at(0),3);
    applyTable1_a(m,a5,19,c4[19]);
    applyTable1_a(m,a5,26,1);
    applyTable1_a(m,a5,27,0);
    applyTable1_a(m,a5,29,1);
    applyTable1_a(m,a5,32,1);

    // Condition 18: d5,19 = a5,19, d5,26 = b4,26, d5,27 = b4,27, d5,29 = b4,29, d5,32 = b4,32
    d5 = GG(d4,a5,b4,c4, m.at(4),5);
    applyTable1_d(m,d5,19,a5[19]);
    applyTable1_d(m,d5,26,b4[26]);
    applyTable1_d(m,d5,27,b4[27]);
    applyTable1_d(m,d5,29,b4[29]);
    applyTable1_d(m,d5,32,b4[32]);

    // Condition 19: c5,26 = d5,26, c5,27 = d5,27, c5,29 = d5,29, c5,30 = d5,30, c5,32 = d5,32
    c5 = GG(c4,d5,a5,b4, m.at(8),9);
    applyTable2(m,c5,26,d5[26]);
    applyTable2(m,c5,27,d5[27]);
    applyTable2(m,c5,29,d5[29]);
    // Cannot apply table 2 to i=30.
    applyTable2(m,c5,32,d5[32]);

}

// i is the 1-based bit position.
bool WangAttack::applyTable1_a(QVector<quint32> & m, HackWord & w, const int i,  int desired)
{
    using namespace qossl;
    if (w[i] == desired) {
        return false;
    }

    if (i<5) {
        qWarning() << "Bad i";
        return false;
    }

    // Step 1
    if (desired) {
        m[0] += (1<<(i - 4 - 1));
    } else {
        m[0] -= (1<<(i - 4 - 1));
    }

    HackWord a1x = a1;
    a1x[i] = desired;

    m[1] = rightrotate(d1, 7) - d0  - F(a1x,b0 ,c0 );  //Step2
    m[2] = rightrotate(c1,11) - c0  - F(d1 ,a1x,b0 );  //Step3
    m[3] = rightrotate(b1,19) - b0  - F(c1 ,d1 ,a1x);  //Step4
    m[4] = rightrotate(a2, 3) - a1x - F(b1 ,c1 ,d1 );  //Step5

    a1 = a1x;

    w[i] = desired;
    this->applyRound1Corrections(m);
    return true;
}

bool WangAttack::applyTable1_d(QVector<quint32> & m, HackWord & w, const int i,  int desired)
{
    using namespace qossl;
    if (w[i] == desired) {
        return false;
    }

    if (i<5) {
        qWarning() << "Bad i";
        return false;
    }

    // Step 1
    if (desired) {
        m[4] += (1<<(i - 1 - 4));
    } else {
        m[4] -= (1<<(i - 1 - 4));
    }

    HackWord a2x = a2;
    a2x[i] = desired;

    m[5] = rightrotate(d2, 7) - d1  - F(a2x,b1 ,c1 );  //Step2
    m[6] = rightrotate(c2,11) - c1  - F(d2 ,a2x,b1 );  //Step3
    m[7] = rightrotate(b3,19) - b1  - F(c2 ,d2 ,a2x);  //Step4
    m[8] = rightrotate(a3, 3) - a2x - F(b2 ,c2 ,d2 );  //Step5

    a2 = a2x;
    w[i] = desired;
    this->applyRound1Corrections(m);
    return true;
}

bool WangAttack::applyTable2(QVector<quint32> & m, HackWord & w, const int i,  bool desired)
{
    using namespace qossl;
    if (w[i] == desired) {
        return false;
    }

    m[5] = m[5] + (1 << (i-17));
    m[8] = m[8] - (1 << (i-10));
    m[9] = m[9] - (1 << (i-10));

    d2[i-9] = 0;
    m[5] = invFF(d1,a2,b1,c1, d2,7);

    a2[i-9] = b1[i-9];
    m[4] = invFF(a1,b1,c1,d1, a2,3);

    c2[i-9] = 0;
    m[6] = invFF(c1,d2,a2,b1, c2,11);

    b2[i-9] = 0;
    m[7] = invFF(b1,c2,d2,a2, b2,19);

    w[i] = desired;
    return true;
}


void TestSet7_55_wang::testChallenge55()
{
    using namespace qossl;

    // Check basic functions
    QCOMPARE(toBytes(fromBytes(Wang::m1)), Wang::m1);
    QCOMPARE(toBytes(fromBytes(Wang::m2)), Wang::m2);

    // Verify Wang's original collisions
    QCOMPARE(Md4::hash(Wang::m1).toHex(), Wang::h1star.toHex());
    QCOMPARE(Md4::hash(Wang::m1dash).toHex(), Wang::h1star.toHex());
    QCOMPARE(Md4::hash(Wang::m2).toHex(), Wang::h2star.toHex());
    QCOMPARE(Md4::hash(Wang::m2dash).toHex(), Wang::h2star.toHex());

    // Check the M -> M' bit flipping is working.
    const QVector<quint32> wangM1 = fromBytes(Wang::m1);
    const QVector<quint32> wangM1dash = fromBytes(Wang::m1dash);
    QCOMPARE(mPrimeFromM(wangM1), wangM1dash);

    const QVector<quint32> wangM2 = fromBytes(Wang::m2);
    const QVector<quint32> wangM2dash = fromBytes(Wang::m2dash);
    QCOMPARE(mPrimeFromM(wangM2), wangM2dash);

    // Do Wangs collisions fulfill the conditions?
    {
        WangAttack checker;
        qDebug() << "Check M1";
        checker.checkM(wangM1);
        qDebug() << "Check M2";
        checker.checkM(wangM2);
        qDebug() << "Check Done";
    }

    // Testing word hacking.
    {
        HackWord t,t2;
        QCOMPARE((bool)t[1], false);
        t[1] = true;
        QCOMPARE((bool)t[1], true);
        t[1] = t2[3];
        QCOMPARE((bool)t[1], false);
        QCOMPARE((quint32)t, (quint32)0);
        t[12] = true;
        QCOMPARE((quint32)t, (quint32)1<<11);
    }

    for (int i=0; i<(1<<20); ++i) {
        QVector<quint32> m = randomBlock();
        WangAttack attacker;
        attacker.modifyM(m);
        QVector<quint32> mP = mPrimeFromM(m);

        WangAttack checker;
        checker.checkM(m);

        break;

        QByteArray mB = toBytes(m);
        QByteArray mBP = toBytes(mP);
        if (Md4::hash(mB) == Md4::hash(mBP)) {
            qDebug() << "Collision" << i
             << mB.toHex()
             << mBP.toHex()
             << Md4::hash(mB);
            break;
        }
    }


}

QVector<quint32> TestSet7_55_wang::mPrimeFromM(const QVector<quint32> &input)
{
    QVector<quint32> output = input;
    output[ 1] = input[ 1] + (1u<<31); // Dm1 = 2^31
    output[ 2] = input[ 2] + (1u<<31) - (1u<<28);  // Dm2 = 2^31 - 2^28
    output[12] = input[12] - (1u<<16); // Dm12 = -2^16
    return output;
}


