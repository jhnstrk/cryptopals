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
    QCOMPARE( QBigInt("-1",10).toString(), QString::number(-1) );
    QCOMPARE( QBigInt("9abcd",16).toString(16), QString::number(0x9abcd, 16) );
    QCOMPARE( QBigInt("9abcdef0123456789abcdef",16).toString(16), QString("9abcdef0123456789abcdef") );

    const QBigInt t1("9abcdef0123456789abcdef",16);
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
    QCOMPARE( (QBigInt("1234567890123456789",10) * 10).toString(10),
              QString( "12345678901234567890") );
    QCOMPARE( (QBigInt("-1234567890123456789",10) * 10).toString(10),
              QString( "-12345678901234567890") );
    QCOMPARE( (QBigInt("1234567890",10) * QBigInt("1000000",10)).toString(10),
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

    QCOMPARE( QBigInt(QByteArray::fromHex("0102030405060708091a1b1c")).toString(16),
              QString("1c1b1a090807060504030201"));
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

    const QBigInt anum = QBigInt(str,base);
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

    const QBigInt anum = QBigInt(number,10);
    const QByteArray bytes = anum.toLittleEndianBytes();
    const QBigInt anum2 = QBigInt(bytes);

    QCOMPARE(anum2, anum);
}

namespace {
    QString Q(const char * x) { return QString(x); }
    QString N(qint64 x) { return QString::number(x); }
}
void TestBigInt::testDivide_data()
{
    QTest::addColumn<QString>("numerator");
    QTest::addColumn<QString>("denominator");
    QTest::addColumn<QString>("quotient");
    QTest::addColumn<QString>("remainder");

    QTest::newRow("0/1")  << N(0) << N( 1) << N(0/ 1) << N(0%1);
    QTest::newRow("0/-1") << N(0) << N(-1) << N(0/-1) << N(0%-1);
    QTest::newRow("1/1")  << N(1) << N( 1) << N(1/ 1) << N(1%1);
    QTest::newRow("1/-1") << N(1) << N(-1) << N(1/-1) << N(1%-1);
    QTest::newRow("-1/1")  << N(-1) << N( 1) << N(-1/ 1) << N(-1%1);
    QTest::newRow("-1/-1") << N(-1) << N(-1) << N(-1/-1) << N(-1%-1);

    QTest::newRow("9/13")   << N( 9) << N( 13) << N( 9/ 13) << N( 9% 13);
    QTest::newRow("9/-13")  << N( 9) << N(-13) << N( 9/-13) << N( 9%-13);
    QTest::newRow("-9/13")  << N(-9) << N( 13) << N(-9/ 13) << N(-9% 13);
    QTest::newRow("-9/-13") << N(-9) << N(-13) << N(-9/-13) << N(-9%-13);

    const qint64 x = (qint64(1) << 41) * 1234;
    QTest::newRow("x/41")   << N( x) << N( 41) << N( x/ 41) << N( x% 41);
    QTest::newRow("x/-41")  << N( x) << N(-41) << N( x/-41) << N( x%-41);
    QTest::newRow("-x/41")  << N(-x) << N( 41) << N(-x/ 41) << N(-x% 41);
    QTest::newRow("-x/-41") << N(-x) << N(-41) << N(-x/-41) << N(-x%-41);

    QTest::newRow("1024/64")   << N( 1024) << N( 64) << N( 1024/ 64) << N( 1024% 64);
    QTest::newRow("1024/-64")  << N( 1024) << N(-64) << N( 1024/-64) << N( 1024%-64);
    QTest::newRow("-1024/64")  << N(-1024) << N( 64) << N(-1024/ 64) << N(-1024% 64);
    QTest::newRow("-1024/-64") << N(-1024) << N(-64) << N(-1024/-64) << N(-1024%-64);

    // According to python:
    QTest::newRow("Big div") << Q("1234568789012098741234124214241242")
                             << Q("12441239876663111")
                             << Q("99231973762346974")
                             << Q("7603865325965128");
}

void TestBigInt::testDivide()
{
    const QFETCH( QString, numerator);
    const QFETCH( QString, denominator);
    const QFETCH( QString, quotient);
    const QFETCH( QString, remainder);

    const QBigInt anum = QBigInt(numerator,10);
    const QBigInt aden = QBigInt(denominator,10);
    const QBigInt quotientA = QBigInt(quotient,10);
    const QBigInt remainderA = QBigInt(remainder,10);

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
    const QBigInt anum("124e51522a31413fd2412ff4123b4",16);
    const QBigInt zero = QBigInt::zero();
    const QBigInt minus100 = QBigInt("-100",10);
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
    QBigInt anum("124e51522a31413fd2412ff4123b4",16);
    QBigInt zero = QBigInt::zero();
    QBigInt minus100 = QBigInt("-100",10);
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
