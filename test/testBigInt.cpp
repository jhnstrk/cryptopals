#include "testBigInt.h"

#include <qbigint.h>

#include <QByteArray>
#include <QDataStream>
#include <QDebug>
#include <QTest>

#include "test.h"

#include <algorithm>
#include <limits>

JDS_ADD_TEST(TestBigInt)

namespace QTest {

    bool qCompare(QBigInt const& actual, QBigInt const& expected,
                                  char const* lStr, char const* rStr, char const* file, int line)
    {
        if (!(actual == expected)) {
            QString statement = QString("Compared values are not the same\n"
                                        "Actual   (%1): %2\n"
                                        "Expected (%3): %4")
                    .arg(lStr,actual.toString(16),rStr,expected.toString(16));
            qFail(statement.toUtf8().constData(),file,line);
            return false;
        }
        return true;
    }
}

void TestBigInt::initTestCase()
{

}

void TestBigInt::cleanupTestCase()
{

}

void TestBigInt::testBasicOperators()
{
    QBigInt inv;
    QVERIFY(!inv.isValid());

    const QBigInt one = QBigInt::one();
    QVERIFY(one == 1);
    QVERIFY(!(one == inv));
    QVERIFY(one != 0);
    QVERIFY(one != inv);
    QCOMPARE( one,  one);
    QCOMPARE( -one,  -one);

    const QBigInt zero = QBigInt::zero();
    QVERIFY(zero == 0);
    QVERIFY(zero != 1);
    QCOMPARE( zero,  zero);

    QVERIFY(zero < one);
    QVERIFY(zero != one);

    const QBigInt otherZero = QBigInt::zero();
    QVERIFY(otherZero == zero);

    const QBigInt otherOne = QBigInt::one();
    QVERIFY(one == otherOne);

    QBigInt two = one + one;
    QVERIFY( two != one);
    QVERIFY( two != inv);
    QVERIFY( two != zero);
    QVERIFY( one < two && zero < two);
    QVERIFY(two == 2);

    QVERIFY( (zero << 100) == zero);
    QVERIFY( (zero >> 100) == zero);
    QVERIFY( (zero + zero) == zero);
    QVERIFY( (zero - zero) == zero);

    QVERIFY( (one - zero) == one);
    QVERIFY( (two - two) == zero);
    QVERIFY( (one - two) == -one);

    QVERIFY( two + two + one == one + one + one + one + one);

    // left shift.
    QVERIFY( (one << 1) == two);
    QVERIFY( (one << 31) == (1u << 31) );
    QCOMPARE( (one << 12).toString(16), QString::number(1LL << 12, 16) );
    QCOMPARE( (one << 12).toString(10), QString::number(1LL << 12, 10) );

    QCOMPARE( (one << 31).toString(16), QString::number(1LL << 31, 16) );
    QCOMPARE( (one << 32).toString(16), QString::number(1LL << 32, 16) );

    QCOMPARE( (one << 33).toString(16), QString::number(1LL << 33, 16) );
    QCOMPARE( (one << 63).toString(16), QString::number(1LL << 63, 16) );

    //right shift
    QCOMPARE( ((one << 13) >> 5).toString(16), QString::number(1LL << 8, 16));
    QCOMPARE( ((one << 312) >> 300).toString(16), QString::number(1LL << 12, 16));

    // from String
    QCOMPARE( QBigInt::fromString("-1",10).toString(), QString::number(-1) );
    QCOMPARE( QBigInt::fromString("9abcd",16).toString(16), QString::number(0x9abcd, 16) );
    QCOMPARE( QBigInt::fromString("9abcdef0123456789abcdef",16).toString(16), QString("9abcdef0123456789abcdef") );

    const QBigInt t1 = QBigInt::fromString("9abcdef0123456789abcdef",16);
    QCOMPARE( (t1 << 36).toString(16), QString("9abcdef0123456789abcdef000000000") );
    QCOMPARE( (t1 << 32).toString(16), QString("9abcdef0123456789abcdef00000000") );
    QCOMPARE( (t1 << 28).toString(16), QString("9abcdef0123456789abcdef0000000") );
    QCOMPARE( (t1 >> 36).toString(16), QString("9abcdef0123456") );
    QCOMPARE( (t1 >> 32).toString(16), QString("9abcdef01234567") );
    QCOMPARE( (t1 >> 28).toString(16), QString("9abcdef012345678") );

    qDebug() << "multiply";
    // multiply
    QVERIFY( one * 2 == two );
    QVERIFY( two * 4 == 8 );
    QVERIFY( (one << 321) * (1 << 12)  == (one << 333) );
    QVERIFY( two * two == 4 );
    QVERIFY( two * -two == -4 );
    QVERIFY( -two * two == -4 );
    QVERIFY( -two * -two == 4 );
    QCOMPARE( -one * two, -two );
    QCOMPARE( (two * two + 1) * 4, QBigInt(20) );

    qDebug() << "Decimal";
    // Decimal numbers
    QCOMPARE( (QBigInt::fromString("1234567890123456789",10) * 10).toString(10),
              QString( "12345678901234567890") );
    QCOMPARE( (QBigInt::fromString("-1234567890123456789",10) * 10).toString(10),
              QString( "-12345678901234567890") );
    QCOMPARE( (QBigInt::fromString("1234567890",10) * QBigInt::fromString("1000000",10)).toString(10),
              QString( "1234567890000000") );

    qDebug() << "Bit Positions";
    QCOMPARE( (QBigInt(0)).highBitPosition(), -1);
    QCOMPARE( (QBigInt(1)).highBitPosition(), 0);
    QCOMPARE( (QBigInt(1) << 1).highBitPosition(), 1);
    QCOMPARE( (QBigInt(1) << 7).highBitPosition(), 7);
    QCOMPARE( (QBigInt(0x10101010)).highBitPosition(), 28);
    QCOMPARE( (QBigInt(0x10101010) << 3).highBitPosition(), 28+3);
    QCOMPARE( (QBigInt(0x10101010) << 123).highBitPosition(), 28 + 123);

    QBigInt test = zero;
    test.setBit(31);
    QCOMPARE(test , QBigInt(1u << 31));
    test.setBit(28);
    QCOMPARE(test , QBigInt((1u << 31) | (1u << 28)));
    test.setBit(123);
    QVERIFY(test.testBit(28));
    QVERIFY(test.testBit(31));
    QVERIFY(test.testBit(123));
    QVERIFY(!test.testBit(321));
    QVERIFY(!test.testBit(0));
    test.setBit(0);
    QVERIFY(test.testBit(0));

    test = QBigInt::one();
    --test;
    QCOMPARE(test, QBigInt(0) );
    --test;
    QCOMPARE(test, QBigInt(-1) );
    --test;
    QCOMPARE(test, QBigInt(-2) );
    ++test;
    ++test;
    QCOMPARE(test, QBigInt(0) );
    ++test;
    QCOMPARE(test, QBigInt(1) );

    test = QBigInt::zero();
    test += 123;
    QCOMPARE(test, QBigInt(123) );
    test -= 130;
    QCOMPARE(test, QBigInt(-7) );

    qDebug() << "pow";
    test = QBigInt(3);
    QCOMPARE(test.exp(QBigInt(4)), QBigInt(3*3*3*3));
    QCOMPARE(QBigInt(2).exp(QBigInt(31)), QBigInt(quint64(1) << 31));

    qDebug() << "modExp";
    test = QBigInt(3);
    QCOMPARE(test.modExp(QBigInt(4), QBigInt(13)), QBigInt((3*3*3*3) % 13));
    QCOMPARE(QBigInt(2).modExp(QBigInt(31), QBigInt(13)), QBigInt((quint64(1) << 31) % 13));

    // Example from wikipedia
    test = QBigInt(4);
    QCOMPARE(test.modExp(QBigInt(13), QBigInt(497)), QBigInt(445));
}

void TestBigInt::testConstructors()
{
    {
        typedef quint32 T;
        QCOMPARE( QBigInt(T(0)).toString(), QString("0") );
        QCOMPARE( QBigInt(std::numeric_limits<T>::max()).toString(),
                  QString::number(std::numeric_limits<T>::max()) );
        QCOMPARE( QBigInt(std::numeric_limits<T>::min()).toString(),
                  QString::number(std::numeric_limits<T>::min()) );
    }
    {
        typedef qint32 T;
        QCOMPARE( QBigInt(T(0)).toString(), QString("0") );
        QCOMPARE( QBigInt(std::numeric_limits<T>::max()).toString(),
                  QString::number(std::numeric_limits<T>::max()) );
        QCOMPARE( QBigInt(std::numeric_limits<T>::min()).toString(),
                  QString::number(std::numeric_limits<T>::min()) );
    }
    {
        typedef quint64 T;
        QCOMPARE( QBigInt(T(0)).toString(), QString("0") );
        QCOMPARE( QBigInt(std::numeric_limits<T>::max()).toString(),
                  QString::number(std::numeric_limits<T>::max()) );
        QCOMPARE( QBigInt(std::numeric_limits<T>::min()).toString(),
                  QString::number(std::numeric_limits<T>::min()) );
    }
    {
        typedef qint64 T;
        QCOMPARE( QBigInt(T(0)).toString(), QString("0") );
        QCOMPARE( QBigInt(std::numeric_limits<T>::max()).toString(),
                  QString::number(std::numeric_limits<T>::max()) );
        QCOMPARE( QBigInt(std::numeric_limits<T>::min()).toString(),
                  QString::number(std::numeric_limits<T>::min()) );
    }
    {
        typedef unsigned char T;
        QCOMPARE( QBigInt(T(0)).toString(), QString("0") );
        QCOMPARE( QBigInt(std::numeric_limits<T>::max()).toString(),
                  QString::number(std::numeric_limits<T>::max()) );
        QCOMPARE( QBigInt(std::numeric_limits<T>::min()).toString(),
                  QString::number(std::numeric_limits<T>::min()) );
    }
    {
        typedef signed char T;
        QCOMPARE( QBigInt(T(0)).toString(), QString("0") );
        QCOMPARE( QBigInt(std::numeric_limits<T>::max()).toString(),
                  QString::number(std::numeric_limits<T>::max()) );
        QCOMPARE( QBigInt(std::numeric_limits<T>::min()).toString(),
                  QString::number(std::numeric_limits<T>::min()) );
    }

    QCOMPARE( QBigInt::fromLittleEndianBytes(QByteArray::fromHex("0102030405060708091a1b1c")).toString(16),
              QString("1c1b1a090807060504030201"));

    // Trailing zeros should be ok.
    QVERIFY( QBigInt::fromLittleEndianBytes(QByteArray::fromHex("000000000000")).isZero() );
    QCOMPARE( QBigInt::fromLittleEndianBytes(QByteArray::fromHex("01000000000000")).toString(),
              QString("1"));
}

void TestBigInt::testString_data()
{
    QTest::addColumn<int>("base");
    QTest::addColumn<QString>("str");

    const quint64 oneTwo30n = (1ull << 30);
    QTest::newRow("0")  << 10    << QString::number(0);
    QTest::newRow("1")  << 10    << QString::number(1);
    QTest::newRow("1<<30,8")  << 8 << QString::number(oneTwo30n,8);
    QTest::newRow("1<<30,5") << 5 << QString::number(oneTwo30n,5);
    QTest::newRow("1<<30,30") << 30 << QString::number(oneTwo30n,30);
    QTest::newRow("1<<30,32") << 32 << QString::number(oneTwo30n,32);
    QTest::newRow("1<<30,2")  << 2 << QString::number(oneTwo30n,2);
    QTest::newRow("1<<30,2") << 16 << QString::number(0x9abcd,16);
    QTest::newRow("-100") << 10 << QString::number(100,16);
}

void TestBigInt::testString()
{
    const QFETCH( int, base);
    const QFETCH( QString, str);

    const QBigInt anum = QBigInt::fromString(str,base);
    const QString actual = anum.toString(base);

    QCOMPARE(actual, str);
}

void TestBigInt::testBytes_data()
{
    QTest::addColumn<QString>("number");

    QTest::newRow("0") << QString("0");
    QTest::newRow("1") << QString("1");
    QTest::newRow("100") << QString("100");
    QTest::newRow("65535") << QString("65535");
    QTest::newRow("3141592") << QString("3141592");
    QTest::newRow("pi-19") << QString("3141592653589793238");
    QTest::newRow("pi-50") << QString("31415926535897932384626433832795028841971693993751");
}

void TestBigInt::testBytes()
{
    const QFETCH( QString, number);

    const QBigInt anum = QBigInt::fromString(number,10);
    const QByteArray bytes = anum.toLittleEndianBytes();
    const QBigInt anum2 = QBigInt::fromLittleEndianBytes(bytes);

    QCOMPARE(anum2, anum);
}

namespace {
    QString Q(const char * x) { return QString(x); }
    QString N(qint64 x) {
        return (x < 0) ? QString("-") + QString::number(-x,16)
                       : QString::number(x,16);
    }
}
void TestBigInt::testDivide_data()
{
    QTest::addColumn<QString>("numerator");
    QTest::addColumn<QString>("denominator");
    QTest::addColumn<QString>("quotient");
    QTest::addColumn<QString>("remainder");
#if 0
    QTest::newRow("0/1")   <<  "0" <<  "1" <<  "0" << "0";
    QTest::newRow("0/-1")  <<  "0" << "-1" <<  "0" << "0";
    QTest::newRow("1/1")   <<  "1" <<  "1" <<  "1" << "0";
    QTest::newRow("1/-1")  <<  "1" << "-1" << "-1" << "0";
    QTest::newRow("-1/1")  << "-1" <<  "1" << "-1" << "0";
    QTest::newRow("-1/-1") << "-1" << "-1" <<  "1" << "0";

    QTest::newRow("8/9")   <<  "8" <<  "9" << "0" <<  "8";
    QTest::newRow("8/-9")  <<  "8" << "-9" << "0" <<  "8";
    QTest::newRow("-8/9")  << "-8" <<  "9" << "0" << "-8";
    QTest::newRow("-8/-9") << "-8" << "-9" << "0" << "-8";

    const qint64 x = (qint64(1) << 41) * 1234;
    QTest::newRow("x/41")   << N( x) << N( 41) << N( x/ 41) << N( x% 41);
    QTest::newRow("x/-41")  << N( x) << N(-41) << N( x/-41) << N( x%-41);
    QTest::newRow("-x/41")  << N(-x) << N( 41) << N(-x/ 41) << N(-x% 41);
    QTest::newRow("-x/-41") << N(-x) << N(-41) << N(-x/-41) << N(-x%-41);

    QTest::newRow("1024/64")   << N( 1024) << N( 64) << N( 1024/ 64) << N( 1024% 64);
    QTest::newRow("1024/-64")  << N( 1024) << N(-64) << N( 1024/-64) << N( 1024%-64);
    QTest::newRow("-1024/64")  << N(-1024) << N( 64) << N(-1024/ 64) << N(-1024% 64);
    QTest::newRow("-1024/-64") << N(-1024) << N(-64) << N(-1024/-64) << N(-1024%-64);

    const QBigInt A = QBigInt::fromString("908723affccc0987988971010019871398710937aaaacccdddffffff097897987097",16);
    const QBigInt B = QBigInt::fromString("fff98131341abcdefdef09891379831ff441122ff",16);

    QTest::newRow("A/A")  << A.toString() << A.toString() << QString("1") << QString("0");
    QTest::newRow("A/-A") << A.toString() << (-A).toString() << QString("-1")  << QString("0");
    QTest::newRow("-A/A")  << (-A).toString() << A.toString() << QString("-1") << QString("0");
    QTest::newRow("-A/-A") << (-A).toString() << (-A).toString() << QString("1") << QString("0");

    QTest::newRow("(A-1)/A")  << (A - 1).toString() << A.toString() << QString("0") << (A - 1).toString();
    QTest::newRow("A/(A-1)") << A.toString() << (A-1).toString() << QString("1") << QString("1");

    // According to python:
    QTest::newRow("Big div") << Q("3cde72e72245ca606d3b35f807da")
                             << Q("2c333de369f747")
                             << Q("1608af452772fde")
                             << Q("1b03acdbac8f48");

    QTest::newRow("Big div2") << Q("114b089ea5164b74af9a29a675ee2b758ba4ee23")
                             << Q("84595161401484a000001")
                             << Q("217320e4fe3377e3854")
                             << Q("10dc0dd8d33aa0c26b5cf");
#endif

// Correct:
    QTest::newRow("Big div3") << Q("325d9d61a05d4305d9434f4a3c62d433949ae6209d4926c3f5bd2db49ef47187094c1a6970ca7e6bd2a73c5534936a8de061e8d4649f4f3235e005b80411640114a88bc491b9fc4ed520190fba035faaba6c356e38a31b5653f445975836cb0b6c975a351a28e4262ce3ce3a0b8df68368ae26a7b7e976a3310fc8f1f9031eb0f669a20288280bda5a580d98089dc1a47fe6b7595fb101a3616b6f4654b31fb6bfdf56deeecb1b896bc8fc51a16bf3fdeb3d814b505ba34c4118ad822a51abe1de3045b7a748e1042c462be695a9f9f2a07a7e89431922bbb9fc96359861c5cd134f451218b65dc60d7233e55c7231d2b9c9fce837d1e43f61f7de16cfb896634ee0ed1440ecc2cd8194c7d1e1a140ac53515c51a88991c4e871ec29f866e7c215bf55b2b722919f001")
     << Q("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff")
     << Q("325d9d61a05d4305e4124d9a5f4910452cd7369c54cd3c06277298415326141a468abdbc30c0cd209198a64105f00c2d852e70dfe79d4c3cb98f8cd2eef56b638518b52091e6460fdc32f11b00bcbd6bac801babcee538f6a28f7c69372c1e8c56be9a5e8dc3bc6eab1")
     << Q("164b0fcf24288c451c8d972e01d23f0cb540ad16b426bd9f68cfe7f64550dcf6528fc83235e8037783b6d7ce09fbf0cdd750be78b6cdac36bd4435fb1f29027971eb0868ced7f77965bdae3fbec6ae4f011ce47bf224814268715e04c3a539a1770be7d67ff7ce4309ea413ae405ba56d798e6a0a163a3b47fe84f32fa6b5d55ff3c34db910f95b7bd0dd6aafc8c86ccf19ab06e3abfa51a927e6846dc2512c1fc7d7ce0c20434e8b7c35cb439913e80ad4cbecbbdafb81fdf01144e64e0dab2");
// Bad:
    QTest::newRow("Big div4") << Q("325d9d61a05d4305d9434f4a3c62d433949ae6209d4926c3f5bd2db49ef47187094c1a6970ca7e6bd2a73c5534936a8de061e8d4649f4f3235e005b80411640114a88bc491b9fc4ed520190fba035faaba6c356e38a31b5653f445975836cb0b6c975a351a28e4262ce3ce3a0b8df68368ae26a7b7e976a3310fc8f1f9031eb0f669a20288280bda5a580d98089dc1a47fe6b7595fb101a3616b6f4654b31fb6bfdf56deeecb1b896bc8fc51a16bf3fdeb3d814b505ba34c4118ad822a51abe1de3045b7a748e1042c462be695a9f9f2a07a7e89431922bbb9fc96359861c5cd134f451218b65dc60d7233e55c7231d2b9c9fce837d1e43f61f7de16cfb896634ee0ed1440ecc2cd8194c7d1e1a140ac53515c51a88991c4e871ec29f866e7c215bf55b2b722919f001")
     << Q("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff")
     << Q("325d9d61a04d4305e4124d9a5f45a142d6f94d287808cbc93f7fb02c39983766fb2120ba9d14b770cac44c0842c3268ad2dce51eb8fae463f5ee3955883645db0a0f9055c7908efb30480f25505527e694596ddc476900e1f206ee9f464d178ead08e4351e65593c931")
     << Q("81499ed7cb12976c81ff76e74579ec0cd97313e8001168f8fdd1853aeb08da3579ecb9b4f1d825aa0d25f8d31f44134c27901fec085fbf0cb5b8d6a9ffb2e2c129ecfbe287781fad742f9623dcd6fe044f28d30eded0713b9b2d7854ef9c71ef7faba77c66a9f89e46cc117b2d216a9cfca78ed57bebb8ad411583aaa52371cfc6f0a345513852573544c98a6a0cc1229aa1d7cb1641ff3f246621ca7b1bab89a20e929af04a23ea40682229a6ae9be5d2a609ff51c99984839e7d587eadb932");
}

void TestBigInt::testDivide()
{
    const QFETCH( QString, numerator);
    const QFETCH( QString, denominator);
    const QFETCH( QString, quotient);
    const QFETCH( QString, remainder);

    const QBigInt anum = QBigInt::fromString(numerator,16);
    const QBigInt aden = QBigInt::fromString(denominator,16);
    const QBigInt quotientA = QBigInt::fromString(quotient,16);
    const QBigInt remainderA = QBigInt::fromString(remainder,16);

    QPair< QBigInt, QBigInt > result = QBigInt::div(anum,aden);

    QCOMPARE( result.first, quotientA );
    QCOMPARE( result.second, remainderA );

    QCOMPARE( anum / aden, quotientA );
    QCOMPARE( anum % aden, remainderA );

    // Check multiply and add is consistent.
    QCOMPARE( quotientA * aden + remainderA, anum);
    QCOMPARE( quotientA * aden, anum - remainderA);
    QCOMPARE( remainderA + (aden * quotientA), anum);
    QCOMPARE( aden * quotientA, anum - remainderA);
}

void TestBigInt::testDivideBad()
{
    QVERIFY( !(QBigInt::zero() / QBigInt::zero()).isValid() );
    QVERIFY( !(QBigInt::one() / QBigInt::zero()).isValid() );
}

void TestBigInt::testMetaType()
{
    const QBigInt anum = QBigInt::fromString("124e51522a31413fd2412ff4123b4",16);
    const QBigInt zero = QBigInt::zero();
    const QBigInt minus100 = QBigInt::fromString("-100",10);
    const QBigInt def = QBigInt();

    QVariantList alist  = QVariantList()
            << QVariant::fromValue(anum)
            << QVariant::fromValue(zero)
            << QVariant::fromValue(minus100)
            << QVariant::fromValue(def);

    QCOMPARE(alist.at(0).value<QBigInt>(), anum);
    QCOMPARE(alist.at(1).value<QBigInt>(), zero);
    QCOMPARE(alist.at(2).value<QBigInt>(), minus100);
    QCOMPARE(alist.at(3).value<QBigInt>(), def);
}

void TestBigInt::testDataStream()
{
    QBigInt anum = QBigInt::fromString("124e51522a31413fd2412ff4123b4",16);
    QBigInt zero = QBigInt::zero();
    QBigInt minus100 = QBigInt::fromString("-100",10);
    QBigInt def = QBigInt();

    QByteArray buffer;
    {
        QDataStream  writer(&buffer,QIODevice::WriteOnly);
        writer << anum << zero << def << minus100;
        writer << anum << zero << def << minus100;
    }

    QDataStream reader(&buffer,QIODevice::ReadOnly);

    // Check we get back what we put in
    QBigInt v;
    reader >> v; QCOMPARE(v, anum);
    reader >> v; QCOMPARE(v, zero);
    reader >> v; QCOMPARE(v, def);
    reader >> v; QCOMPARE(v, minus100);
    reader >> v; QCOMPARE(v, anum);
    reader >> v; QCOMPARE(v, zero);
    reader >> v; QCOMPARE(v, def);
    reader >> v; QCOMPARE(v, minus100);
}
