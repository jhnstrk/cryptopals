#include "testSet6_dsa.h"

#include <qbigint.h>
#include <dsa.h>
#include <utils.h>

#include <QDebug>
#include <QCryptographicHash>
#include <QTest>

#include "test.h"

JDS_ADD_TEST(TestSet6_Dsa)
namespace {
    const char * const p43 = "800000000000000089e1855218a0e7dac38136ffafa72eda7"
            "859f2171e25e65eac698c1702578b07dc2a1076da241c76c6"
            "2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe"
            "ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2"
            "b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87"
            "1a584471bb1";

    const char * const q43 = "f4f47f05794b256174bba6e9b396a7707e563c5b";

    const char * const g43 = "5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119"
            "458fef538b8fa4046c8db53039db620c094c9fa077ef389b5"
            "322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047"
            "0f5b64c36b625a097f1651fe775323556fe00b3608c887892"
            "878480e99041be601a62166ca6894bdd41a7054ec89f756ba"
            "9fc95302291";

    Dsa::Parameters getChallenge43Param()
    {
        Dsa::Parameters param;
        param.g = QBigInt::fromString(g43,16);
        param.p = QBigInt::fromString(p43,16);
        param.q = QBigInt::fromString(q43,16);
        return param;
    }

    QByteArray sha1Hash(const QByteArray & data) {
        return QCryptographicHash::hash(data, QCryptographicHash::Sha1);
    }
}

void TestSet6_Dsa::testBasicDsa()
{
    const Dsa::Parameters param(getChallenge43Param());

    const Dsa::KeyPair key = Dsa::dsaKeyGen(param);

    const QBigInt messageHash = QBigInt::fromBigEndianBytes(sha1Hash("Hello World"));

    Dsa::Signature sig = Dsa::signHash(key.second, messageHash);

    // Genuine signature: OK
    QVERIFY( Dsa::verifyMessageSignature(key.first, sig, messageHash) );

    // Bad message: Not OK
    const QBigInt otherHash = QBigInt::fromBigEndianBytes(sha1Hash("Not World"));
    QVERIFY(!Dsa::verifyMessageSignature(key.first, sig, otherHash) );

    // Sign with another (valid) key.
    const Dsa::KeyPair otherKey = Dsa::dsaKeyGen(param);
    const Dsa::Signature otherSig = Dsa::signHash(otherKey.second, messageHash);

    // Veriying first signature against the second key fails
    QVERIFY( !Dsa::verifyMessageSignature(otherKey.first, sig, messageHash) );

    // Veriying second signature against the first key fails
    QVERIFY( !Dsa::verifyMessageSignature(key.first, otherSig, messageHash) );

    // Veriying second signature against the second key succeeds
    QVERIFY( Dsa::verifyMessageSignature(otherKey.first, otherSig, messageHash) );
}

namespace {
    QBigInt xFromK( const Dsa::Parameters & param, const QBigInt & r,
                    const QBigInt & s, const QBigInt & hm,
                    const QBigInt & k)
    {
        const QBigInt & q = param.q;

        // Reverse the signature process.
        // return ( ( (s * k ) - hm) / r ) % q;
        // Note: Division becomes multiplicative inverse.
        QBigInt ret = ( QBigInt::invmod(r,q) * ( (s * k ) - hm) ) % q;
        if (ret.isNegative()) {
            ret += q;
        }
        return ret;
    }

    Dsa::Signature signHashWithFixedNonce(const Dsa::PrivKey &key, const QBigInt &Hm, const QBigInt &k)
    {
        const QBigInt & x = key.x;
        const QBigInt & p = key.param.p;
        const QBigInt & q = key.param.q;
        const QBigInt & g = key.param.g;

        const QBigInt r = g.modExp(k,p) % q;

        const QBigInt s = (QBigInt::invmod(k,q) * (Hm + x * r)) % q;

        const Dsa::Signature ret(r,s);
        return ret;
    }

}

void TestSet6_Dsa::testChallenge43()
{
    const Dsa::Parameters param(getChallenge43Param());

    const QBigInt y = QBigInt::fromString(
          "84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4"
          "abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004"
          "e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed"
          "1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b"
          "bb283e6633451e535c45513b2d33c99ea17",16);

    const QByteArray message = "For those that envy a MC it can be hazardous to your health\n"
            "So be friendly, a matter of life and death, just like a etch-a-sketch\n";

    const QByteArray hashMessage = sha1Hash(message);
    QCOMPARE( hashMessage, QByteArray::fromHex("d2d0714f014a9784047eaeccf956520045c45265"));

    // These look like base-10, though it's not specified.
    const QBigInt r = QBigInt::fromString(
                "548099063082341131477253921760299949438196259240",10);
    const QBigInt s = QBigInt::fromString(
                "857042759984254168557880549501802188789837994940",10);
    const Dsa::Signature signature(r,s);

    const QBigInt hm = QBigInt::fromBigEndianBytes(hashMessage);

    // Skip 0, it's not allowed by DSA.
    Dsa::PrivKey recoveredKey;
    recoveredKey.param = param;

    QBigInt recoveredK;

    // Skip a few values ;) so that the test completes quicker...
    for (unsigned int k=16000; k < (1<<16); ++k) {
        const QBigInt x = xFromK(param, r, s, hm, QBigInt(k));
        recoveredKey.x = x;

        // See if the recovered public key matches.
        // Could be quicker than checking the signature, as no invmod is needed.
        // But it isn't. Invmod is faster than modExp here.
//        const QBigInt y_test = param.g.modExp(x,param.p);
//        if (y_test == y) {
//            qDebug() << "Key is good, nonce was" << k;
//            qDebug() << x.toString(16);
//            recoveredK = QBigInt(k);
//            break;
//        }

        const Dsa::Signature testSignature = signHashWithFixedNonce(recoveredKey,hm,QBigInt(k));

        if ( (testSignature.r == r)  && (testSignature.s == s) )
        {
            qDebug() << "Key is good, nonce was" << k;
            qDebug() << "x =" << x.toString(16);
            recoveredK = QBigInt(k);
            break;
        }

        if (k%1024 == 0) {
            qDebug() << k;
        }
    }

    QVERIFY(recoveredK.isValid());

    // Its SHA-1 fingerprint (after being converted to hex) is:
    QCOMPARE(sha1Hash(recoveredKey.x.toString(16).toUtf8()).toHex(),
             QByteArray("0954edd5e0afe5542a4adf012611a91912a3ec16"));

    const Dsa::Signature testSignature = signHashWithFixedNonce(recoveredKey,hm,recoveredK);

    QCOMPARE( testSignature.r.toString(), r.toString());
    QCOMPARE( testSignature.s.toString(), s.toString());
    qDebug() << "Recovered key generates correct signature";

     // Also confirm the public key, derived from the private key, matches:
    const QBigInt y_test = param.g.modExp(recoveredKey.x,param.p);
    QCOMPARE(y_test.toString(16), y.toString(16));

    // x = 15fb2873d16b3e129ff76d0918fd7ada54659e49
}


namespace Challenge44 {
    struct Entry {
        QByteArray msg;
        Dsa::Signature sig;
        QBigInt m;
    };

    QPair< QByteArray, QByteArray > splitLine(const QByteArray & line){
        typedef QPair< QByteArray, QByteArray >    ReturnType;
        int ix = line.indexOf(':');
        if (ix == -1) {
            return ReturnType();
        }
        return ReturnType(line.mid(0,ix), line.mid(ix+1));
    }
}
void TestSet6_Dsa::testChallenge44()
{
    using namespace Challenge44;

    QVector<Entry> entries;

    QFile file(":/qossl_test_resources/rsc/set6/44.txt");
    QVERIFY(file.open(QIODevice::ReadOnly));
    while (file.isReadable() && !file.atEnd()) {

        Entry e;
        QByteArray line = file.readLine();
        e.msg = splitLine(line).second;
        QVERIFY(splitLine(line).first == "msg");
        line = file.readLine();
        e.sig.s = QBigInt::fromString(splitLine(line).second.trimmed(),10);
        QVERIFY(splitLine(line).first == "s");
        line = file.readLine();
        e.sig.r = QBigInt::fromString(splitLine(line).second.trimmed(),10);
        QVERIFY(splitLine(line).first == "r");
        line = file.readLine();
        e.m = QBigInt::fromString(splitLine(line).second.trimmed(),16);
        QVERIFY(splitLine(line).first == "m");
        if (e.msg.startsWith(' ')) {
            e.msg = e.msg.mid(1);
        }
        entries.push_back(e);
    }
    file.close();


    const Dsa::Parameters param(getChallenge43Param());
    const QBigInt & q = param.q;
    const QBigInt y = QBigInt::fromString(
                "2d026f4bf30195ede3a088da85e398ef869611d0f68f07"
                "13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8"
                "5519b1c23cc3ecdc6062650462e3063bd179c2a6581519"
                "f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430"
                "f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3"
                "2971c3de5084cce04a2e147821",16);

    Dsa::PubKey pubKey;
    pubKey.y = y;
    pubKey.param = param;

    typedef QHash< QBigInt, QList< int > > HashType;
    QHash< QBigInt, QList< int > > rHash;

    // Theory:
    // Since we have:    s = k^-1 (H(m) + xr) % q
    // if two messages use the same k, take the difference and we get:
    //     s1 - s2 = (k^-1(H(m1) + xr) - k^-1(H(m2) + xr)) %q
    //     k(s1-s2) = (H(m1) - H(m2) +xr - xr ) %q
    //     k(s1-s2) = (H(m1) - H(m2)) %q
    //
    // Since the r value only depends on k, repeated r means same k.

    // For each pair of messages, determine k, if possible.
    for (int i=0; i<entries.size()-1; ++i) {
        const Entry e1 = entries.at(i);

        // Just checking.
        QVERIFY(Dsa::verifyMessageSignature(pubKey,e1.sig,e1.m));

        rHash[e1.sig.r].append( i );

    }

    Dsa::PrivKey priv;
    priv.param = param;

    for (HashType::const_iterator it(rHash.constBegin());
         it != rHash.constEnd(); ++it)
    {
        if (it.value().size() > 1) {
            const Entry e1 = entries.at(it.value().at(0));
            const Entry e2 = entries.at(it.value().at(1));
            QBigInt ds = ( e1.sig.s - e2.sig.s) % q;
            if (ds.isNegative()) {
                ds += q;
            }
            QBigInt dm = ( e1.m - e2.m) % q;
            if (dm.isNegative()) {
                dm += q;
            }

            QList<int> values = it.value();
            std::sort(values.begin(), values.end());
            const QBigInt k = QBigInt::invmod( ds,q ) * dm % q;
            qDebug() << "k = " << k.toString(16) << "used for messages" << values;

            // Use k to derive x; use first match.
            // We know s = k^-1 (H(m) + xr) % q
            // so
            //    x = r^-1 ( sk - H(m) ) % q
            QBigInt x = QBigInt::invmod(e1.sig.r,q) * (e1.sig.s * k - e1.m) % q;
            if (x.isNegative()) {
                x += q;
            }
            qDebug() << "x = " << x.toString(16);
            // Check same x is recovered.
            if (priv.x.isValid()) {
                QCOMPARE(priv.x.toBigEndianBytes(), x.toBigEndianBytes());
            } else {
                priv.x = x;
            }
        }
    }

    // Check we got the right x
    QCOMPARE( sha1Hash(priv.x.toString(16).toUtf8()).toHex(),
              QByteArray("ca8f6f7c66fa362d40760d135b763eb8527d3d52"));

    // x = f1b733db159c66bce071d21e044a48b0e4c1665a
}
