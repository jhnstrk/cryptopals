// Todo: Check INT_MIN,
#pragma once

#include <QObject>

class TestBigInt: public QObject
{
    Q_OBJECT
private slots:
    void initTestCase();
    void cleanupTestCase();

    void testBasicOperators();

    void testConstructors();

    void testString_data();
    void testString();

    void testBytes_data();
    void testBytes();

    void testDivide_data();
    void testDivide();

    void testDivideBad();

    void testInvMod_data();
    void testInvMod();
    
    void testNthRoot_data();
    void testNthRoot();

    void testBitWiseOps();

    void testMetaType();
    void testDataStream();
};
