#include "testBigInt.h"

#include <qbigint.h>

#include <QByteArray>
#include <QDebug>
#include <QTest>

#include "test.h"

#include <algorithm>

JDS_ADD_TEST(TestBigInt)

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

    const QBigInt zero = QBigInt::zero();
    QVERIFY(zero == 0);
    QVERIFY(zero != 1);

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

    QVERIFY( two + two + one == one + one + one + one + one);

    QVERIFY( (one << 1) == two);
    QVERIFY( (one << 31) == (1 << 31) );
    QCOMPARE( (one << 12).toString(16), QString::number(1LL << 12, 16) );
    QCOMPARE( (one << 12).toString(10), QString::number(1LL << 12, 10) );

    QCOMPARE( (one << 31).toString(16), QString::number(1LL << 31, 16) );
    QCOMPARE( (one << 32).toString(16), QString::number(1LL << 32, 16) );

    QCOMPARE( (one << 33).toString(16), QString::number(1LL << 33, 16) );
    QCOMPARE( (one << 63).toString(16), QString::number(1LL << 63, 16) );

    // Random number bases.
    QCOMPARE( (one << 13).toString(8), QString::number(1LL << 13, 8) );
    QCOMPARE( (one << 13).toString(5), QString::number(1LL << 13, 5) );
    QCOMPARE( (one << 13).toString(30), QString::number(1LL << 13, 30) );
    QCOMPARE( (one << 13).toString(32), QString::number(1LL << 13, 32) );
    QCOMPARE( ((one+two +two) << 1).toString(2), QString::number(5LL << 1, 2) );

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

