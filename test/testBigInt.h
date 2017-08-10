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

    void testString_data();
    void testString();

};
