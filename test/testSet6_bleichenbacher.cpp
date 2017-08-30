#include "testSet6_bleichenbacher.h"

#include <qbigint.h>
#include <rsa.h>
#include <utils.h>

#include <QDebug>
#include <QTest>

#include "test.h"

JDS_ADD_TEST(TestSet6_bleichenbacher)


namespace {
    class Pkcs1_Oracle {
    public:
        Pkcs1_Oracle() {
            if (m_fixed) {
                m_privKey.d = QBigInt::fromString("849ada64ffd1056e60427d6479e733f10b57cf920546dda7c0839f67602728fb",16);
                m_pubKey.e = QBigInt(3);
                m_pubKey.n = QBigInt::fromString("c6e847977fb988259063bc16b6dacdeb5530dff9e1c6fe683e0c2494071ea9cb",16);
                m_privKey.n = m_pubKey.n;
            }else {
                Rsa::KeyPair keys = Rsa::rsaKeyGen(128);
                m_privKey = keys.second;
                m_pubKey = keys.first;
            }
            qDebug() << "d" << m_privKey.d.toBigEndianBytes().toHex();
            qDebug() << "e" << m_pubKey.e.toBigEndianBytes().toHex();
            qDebug() << "n" << m_pubKey.n.toBigEndianBytes().toHex();

            m_keyLenBytes = (m_pubKey.n.highBitPosition() + 7 )/8;

        }

        // The oracle function... Return true if encrypted message input is padded ok.
        bool test(const QBigInt & enc) const {
            const QBigInt dec = Rsa::decrypt(m_privKey,enc);
            return this->isPaddingOk(dec);
        }

        // Simplified test for PKCS#1v1.5 validity.
        static bool isPaddingOk(const QBigInt & plain, const int len) {
            const QByteArray bytes = plain.toBigEndianBytes(); // Leading zeros get dropped.
            //qDebug() << bytes.size() << (int)bytes.at(0);
            return ( (bytes.size() == len -1) && (bytes.startsWith((char)0x02)));
            
            // return (plain >> (8*(len - 2))) == 2;
        }

        bool isPaddingOk(const QBigInt & plain) const {
            return isPaddingOk(plain,m_keyLenBytes);
        }

        static QBigInt pkcs1_pad(const QBigInt & message, const int len) {
            const int messageByteCount = (message.highBitPosition() + 7) / 8;
            const int numPad = len - messageByteCount - 3; // 0,2,n * x, 0, m
            if (numPad < 0) {
                qWarning() << "Message too long to pad correctly";
                return message; // invalid. Warn? throw?
            }
            QByteArray padBytes;
            padBytes.append((char)2);
            if (m_fixed) {
                padBytes.append(QByteArray(numPad, (char)0xFF)); // Not random for testing
            } else {
                padBytes.append( qossl::randomBytes(numPad).replace((char)0,(char(1))));
            }
            padBytes.append((char)0);
            QByteArray messageBytes = padBytes + message.toBigEndianBytes();
            return QBigInt::fromBigEndianBytes( messageBytes );
        }

        QBigInt pkcs1_pad(const QBigInt & message) const {
            return pkcs1_pad(message,m_keyLenBytes);
        }

        QBigInt padAndEncrypt(const QBigInt & m) const {
            const QBigInt padded  = this->pkcs1_pad(m);
            qDebug() << "Padded plain" << padded;
            const QBigInt enc = Rsa::encrypt(this->pubKey(), padded);
            return enc;
        }

        const Rsa::PubKey & pubKey() const { return m_pubKey; }
        int keyLenBytes() const { return m_keyLenBytes; }

        // Debugging: All randomness removed.
        bool isFixed() const { return m_fixed; }
    private:
        static const bool m_fixed;
        int m_keyLenBytes;
        Rsa::PrivKey m_privKey;
        Rsa::PubKey m_pubKey;
    };

    const bool Pkcs1_Oracle::m_fixed = true;

    struct Interval {
        Interval(){}
        Interval(const QBigInt & l, const QBigInt & h)
        : low(l), high(h)
        {
        }

        QBigInt low,high;
    };

    bool operator<(const Interval & a, const Interval & b) {
        if (a.low < b.low) {
            return true;
        }
        if (b.low < a.low) {
            return false;
        }
        if (a.high < b.high) {
            return true;
        }
        if (b.high < a.high) {
            return false;
        }
        return false;
    }

    bool overlaps(const Interval & a, const Interval & b) {
        if (a.high < b.low) {
            return false;
        }
        if (b.high < a.low) {
            return false;
        }
        return true;
    }


    QDebug operator<< (QDebug dbg, const Interval & item)
    {
        dbg.nospace() << '['
            << item.low.toBigEndianBytes().toHex()
            <<  ','
            << item.high.toBigEndianBytes().toHex()
            << ']';
        return dbg.maybeSpace();
    }

    class Bleichenbacher {
        public:
        Bleichenbacher(const Pkcs1_Oracle & oracle) :
            m_oracle(oracle),
            m_B( (QBigInt::one() << (8*(oracle.keyLenBytes() - 2))) ),
            m_twoB( 2* m_B ),
            m_threeB( 3 * m_B)
        {

        }

        QBigInt findM(const QBigInt & c)
        {
            // Store some aliases with short variable names.
            const QBigInt & n = m_oracle.pubKey().n;
            const QBigInt & e = m_oracle.pubKey().e;

            const QBigInt s0 = this->find_s0(c);
            // Another candidate is
            // "2b770f3ecbe420aacf98a60ad356c96737e7bfc54bbfd7205bbf860a35a309"
            qDebug() << "s0:" << s0.toBigEndianBytes().toHex();

            const QBigInt c0 = (c * s0.powm(e,n)) % n;
            const Interval M0( m_twoB, m_threeB - 1);
            int i = 1;

            QBigInt s1 = find_s1(c0);
            qDebug() << "s1" << s1.toBigEndianBytes().toHex();
            QBigInt s_i = s1;
            QVector<Interval> M;
            M.append(M0);
            for (; i< 1024; ++i) {
                M = this->updateM(M,s_i);
                qDebug() << "s_i:" << s_i;
                qDebug() << "M:" << M;
                if (M.size() == 1) {
                    if (M.at(0).high == M.at(0).low) {
                        qDebug() << "Result!";
                        return M.at(0).high;
                    }

                    s_i = find_s_i(c0, M.at(0), s_i);
                } else if (M.size() > 1) {
                    s_i = find_si_2b(c0, s_i);
                } else {
                    qWarning() << "Epic badness, M is empty";
                    return QBigInt();
                }

            }
            return QBigInt();

        }
    private:
        // Step 1
        QBigInt find_s0(const QBigInt & c) const {
            const int nN = m_oracle.keyLenBytes();
            const QBigInt &n = m_oracle.pubKey().n;
            const QBigInt &e = m_oracle.pubKey().e;
            if (m_oracle.test(c)) {
                return QBigInt::one();
            }
            for (int i=0; i<8*0xFFFF; ++i) {
                const QBigInt s0_test = QBigInt::fromBigEndianBytes(
                            qossl::randomBytes(nN - 1));
                const QBigInt c0_test = (c * s0_test.powm(e,n)) % n;
                if (m_oracle.test(c0_test)) {
                    return s0_test;
                }
                if (i%1024 == 0) {
                    qDebug() << "Searching for s0" << i;
                }
            }
            qWarning() << "No candidate s0";
            return QBigInt();
        }

        // Step 2a
        QBigInt find_s1(const QBigInt & c0) {
            if (m_oracle.isFixed()) {
                return QBigInt(0xc6e9);
            }
            const QBigInt &n = m_oracle.pubKey().n;
            const QBigInt &e = m_oracle.pubKey().e;

            QBigInt s1 = divRoundUp(n,m_threeB);

            for (int i=0; i<0xffff; ++i) {
                QBigInt c = (c0 * s1.powm(e,n)) % n;
                if (m_oracle.test(c)) {
                    return s1;
                }
                ++s1;
                if (i%1024 == 0) {
                    qDebug() << "Searching for s1" << i;
                }
            }
            qWarning() << "No candidate s1";
            return QBigInt();
        }

        // Step 2b
        QBigInt find_si_2b(const QBigInt & c0, const QBigInt & s_i_1) {
            const QBigInt &n = m_oracle.pubKey().n;
            const QBigInt &e = m_oracle.pubKey().e;

            for (QBigInt si = s_i_1 + 1; si < n ; ++si) {
                QBigInt c = (c0 * si.powm(e,n)) % n;
                if (m_oracle.test(c)) {
                    return si;
                }
                if (si%1024 == 0) {
                    qDebug() << "Searching for si (2b)" << si.toString(16);
                }
            }
            qWarning() << "No candidate si";
            return QBigInt();
        }

        // Step 2c
        QBigInt find_s_i(const QBigInt & c0, const Interval & M_1, const QBigInt & s_i_1) {
            const QBigInt &n = m_oracle.pubKey().n;
            const QBigInt &e = m_oracle.pubKey().e;
            const QBigInt &a = M_1.low;
            const QBigInt &b = M_1.high;
            const QBigInt &twoB = m_twoB;
            const QBigInt &threeB = m_threeB;

            const QBigInt r = divRoundUp( 2 * (b*s_i_1 - twoB) , n);

            QBigInt rin = r*n;

            for (int i = 0;  ; rin += n, ++i ) {
                const QBigInt sin_low = divRoundUp(twoB + rin,b);
                const QBigInt sin_high = divRoundUp(threeB + rin,a);
                for (QBigInt si = sin_low; si < sin_high; ++si, ++i) {
                    const QBigInt c = (c0 * si.powm(e,n)) % n;
                    if (m_oracle.test(c)) {
                        return si;
                    }
                    if (i%0x1000 == 0) {
                        qDebug() << "r" << (rin/n) << "s:" << sin_low << sin_high << si;
                    }
                }
            }

            qWarning() << "No candidate si";
            return QBigInt();
        }

        // Step 3
        QVector<Interval> updateM( const QVector<Interval> & oldM, const QBigInt & s_i){
            QVector<Interval> ret;
            const QBigInt &n = m_oracle.pubKey().n;
            const QBigInt &twoB = m_twoB;
            const QBigInt &threeB = m_threeB;

            foreach (const Interval & M_i_1, oldM) {
                const QBigInt & a = M_i_1.low;
                const QBigInt & b = M_i_1.high;
                const QBigInt r_min = divRoundUp(a*s_i - threeB + 1, n);
                const QBigInt r_max = divRoundDown(b*s_i - twoB, n);

                const DivRemType a1_min = QBigInt::divRem(divRoundUp(twoB + r_min*n, s_i), n);
                const DivRemType a1_max = QBigInt::divRem(divRoundUp(twoB + r_max*n, s_i), n);

                const DivRemType b1_min = QBigInt::divRem(divRoundDown(threeB - 1 + r_min*n, s_i),n);
                const DivRemType b1_max = QBigInt::divRem(divRoundDown(threeB - 1 + r_max*n, s_i),n);

                const bool a1_wrapped = a1_min.first != a1_max.first;
                const bool b1_wrapped = b1_min.first != b1_max.first;

                QVector<QBigInt> addRn;
                if (a1_wrapped) {
                    // There is a value of rn for which (2B + rn) /s_i == n -  1
                    //  => rn = n - s_i - 2B;
                    addRn.append(n*s_i - s_i - twoB);
                    addRn.append(n*s_i - twoB);
                }
                if (b1_wrapped) {
                    // There is a value of rn for which (3B - 1 + rn) /s_i == n -  1
                    //  => rn = n s_i - s_i + 1 - 3B;
                    addRn.append(n*s_i - s_i + 1 - threeB);
                    addRn.append(n*s_i + 1 - threeB);
                }
                {
                    const QBigInt an = std::max(a,a1_min.second);
                    const QBigInt bn = std::min(b,b1_max.second);

                    const Interval i1(an,bn);
                    qDebug() << "r_max" << r_max;
                    qDebug() << "r_min" << r_min;
                    qDebug() << "a1_min" << a1_min;
                    qDebug() << "a1_max" << a1_max;
                    qDebug() << "b1_min" << b1_min;
                    qDebug() << "b1_max" << b1_max;
                    qDebug() << "a" << a;
                    qDebug() << "b" << b;
                    qDebug() << "i1" << i1;
                    if (an > bn) {
                        qWarning() << "Fail an > bn" << an << bn;
                        exit(1);
                    }                    mergeInterval(ret,i1);
                    qDebug() << "ret" << ret;
                }

                if (!addRn.isEmpty()) {
                    qDebug() << "Wrapped";
                }
                foreach (const QBigInt & rn, addRn) {
                    const QBigInt a1 = divRoundUp(twoB + rn, s_i) % n;
                    const QBigInt b1 = divRoundDown(threeB - 1 + rn, s_i) %n;
                    const QBigInt an = std::max(a,a1);
                    const QBigInt bn = std::min(b,b1);

                    Interval i2(an,bn);
                    mergeInterval(ret,i2);
                }

            }

            return ret;
        }

        void mergeInterval(QVector<Interval> & M, const Interval & mi) {
            if (M.isEmpty()) {
                M.append( mi );
                return;
            }
            // TODO: Use 'lower_bound' as starting point.
            for (int i=0; i<M.size(); ++i) {
                Interval & M_i(M[i]);
                if (overlaps(mi, M_i)) {
                    if ((M_i.low <= mi.low) && (M_i.high >= mi.high)) {
                        // New interval is contained in an existing one.
                        return;
                    }

                    if (mi.low < M_i.low) {
                        M_i.low = mi.low;
                    }
                    if (mi.high > M_i.high) {
                        M_i.high = mi.high;
                        QBigInt ubound;
                        int numErase = 0;
                        for (int j = i+1; j<M.size(); ++j) {
                            if (M.at(j).low <= mi.high) {
                                ++numErase;
                                ubound = M.at(j).high;
                            }
                        }
                        if (numErase != 0) {
                            M_i.high = ubound;
                            M.erase(M.begin() + i + 1, M.begin() + i + 1 + numErase);
                            return;
                        }
                    }
                }
            }

            // If we got here, the new interval does not overlap an existing one.
            M.insert(std::upper_bound(M.begin(), M.end(),mi), mi);
        }

        QBigInt divRoundUp(const QBigInt & a, const QBigInt & b)
        {
            const QPair<QBigInt,QBigInt> qr = QBigInt::divRem(a,b);  // a/b
            QBigInt s1 = qr.first;
            if (!qr.second.isZero()) {
                ++s1;
            }
            return s1;
        }

        QBigInt divRoundDown(const QBigInt & a, const QBigInt & b)
        {
            const QPair<QBigInt,QBigInt> qr = QBigInt::divRem(a,b);  // a/b
            QBigInt s1 = qr.first;
            // Truncation; rounds down.
            // if (!qr.second.isZero()) {
                //--s1;
            // }
            return s1;
        }

        private:
        const Pkcs1_Oracle & m_oracle;
        const QBigInt m_B, m_twoB, m_threeB;  // B , 2B, 3B
    };


}

void TestSet6_bleichenbacher::testPaddingOracle()
{
    const QByteArray msg = "Foo";
    const int nBytes = 64;
    QBigInt paddedFooNum = Pkcs1_Oracle::pkcs1_pad(QBigInt::fromBigEndianBytes(msg), nBytes);
    const QByteArray paddedFooBytes = paddedFooNum.toBigEndianBytes();

    QCOMPARE(paddedFooBytes.size(), nBytes-1);
    QCOMPARE(paddedFooBytes.at(0), (char)0x02);
    QCOMPARE(paddedFooBytes.indexOf((char)0x0), paddedFooBytes.size() - msg.size() - 1);
    QVERIFY(paddedFooBytes.endsWith(msg));

    QVERIFY(Pkcs1_Oracle::isPaddingOk(paddedFooNum,nBytes));
    QVERIFY(!Pkcs1_Oracle::isPaddingOk(QBigInt(1),64));
    QVERIFY(!Pkcs1_Oracle::isPaddingOk(QBigInt::fromString("3456789123123123123",16),64));

    Pkcs1_Oracle oracle;
    const QByteArray shortMessage = "kick it, CC";
    const QBigInt paddedShortMessage  = oracle.pkcs1_pad(QBigInt::fromBigEndianBytes(shortMessage));
    const QBigInt enc = Rsa::encrypt(oracle.pubKey(), paddedShortMessage);
    QVERIFY(oracle.test(enc));
    // There is a tiny possibility this is a valid encyrpted message. But really not likely.
    QVERIFY(!oracle.test(QBigInt::fromString("3456789123123123123",16)));
}

void TestSet6_bleichenbacher::testChallenge47()
{
    Pkcs1_Oracle oracle;

    const QByteArray m0Bytes = "unknown";   // The message text;
    const QBigInt m0 = QBigInt::fromBigEndianBytes(m0Bytes);
    const QBigInt c0 = oracle.padAndEncrypt(m0);

    Bleichenbacher attacker(oracle);
    QBigInt recovered = attacker.findM(c0);

    QVERIFY(recovered == m0);
    
}

