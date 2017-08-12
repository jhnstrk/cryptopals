#include "testBigInt.h"

#include <qbigint.h>

#include <QByteArray>
#include <QDebug>
#include <QTest>

#include "test.h"

#include <algorithm>

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
    QVERIFY( (one << 31) == (1 << 31) );
    QCOMPARE( (one << 12).toString(16), QString::number(1LL << 12, 16) );
    QCOMPARE( (one << 12).toString(10), QString::number(1LL << 12, 10) );

    QCOMPARE( (one << 31).toString(16), QString::number(1LL << 31, 16) );
    QCOMPARE( (one << 32).toString(16), QString::number(1LL << 32, 16) );

    QCOMPARE( (one << 33).toString(16), QString::number(1LL << 33, 16) );
    QCOMPARE( (one << 63).toString(16), QString::number(1LL << 63, 16) );

    //right shift
    QCOMPARE( ((one << 13) >> 5).toString(16), QString::number(1LL << 8, 16));
    QCOMPARE( ((one << 312) >> 300).toString(16), QString::number(1LL << 12, 16));

    // toString: number bases.
    QCOMPARE( (one << 13).toString(8), QString::number(1LL << 13, 8) );
    QCOMPARE( (one << 13).toString(5), QString::number(1LL << 13, 5) );
    QCOMPARE( (one << 13).toString(30), QString::number(1LL << 13, 30) );
    QCOMPARE( (one << 13).toString(32), QString::number(1LL << 13, 32) );
    QCOMPARE( ((one+two +two) << 1).toString(2), QString::number(5LL << 1, 2) );
    QCOMPARE( QBigInt(0x9abcd).toString(16), QString::number(0x9abcd, 16) );
    QCOMPARE( (-one).toString(10), QString::number(-1) );

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

    // multiply
    QVERIFY( one * 2 == two );
    QVERIFY( two * 4 == 8 );
    QVERIFY( (one << 321) * (1 << 12)  == (one << 333) );
    QVERIFY( two * two == 4 );
    QCOMPARE( -one * two, -two );
    QCOMPARE( (two * two + 1) * 4, QBigInt(20) );

    // Decimal numbers
    QCOMPARE( (QBigInt("1234567890123456789",10) * 10).toString(10),
              QString( "12345678901234567890") );
    QCOMPARE( (QBigInt("-1234567890123456789",10) * 10).toString(10),
              QString( "-12345678901234567890") );
}

void TestBigInt::testString_data()
{
    QTest::addColumn<qint64>("v");
    QTest::addColumn<int>("base");
    QTest::addColumn<QString>("str");

    QTest::newRow("0")  << qint64(0)  << 10    << QString::number(0);
    QTest::newRow("1")  << qint64(1)  << 10    << QString::number(1);
}

void TestBigInt::testString()
{
    const QFETCH( qint64, v);
    const QFETCH( int, base);
    const QFETCH( QString, str);

    const QBigInt anum = QBigInt(v);
    const QString actual = anum.toString(base);

    QCOMPARE(actual, str);
}

