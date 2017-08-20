#pragma once

#include <QObject>

class TestSet5_Rsa: public QObject
{
    Q_OBJECT
private slots:
    void initTestCase() {}
    void cleanupTestCase() {}

    void testPrimeGen();

    void testBasicRsa_data();
    void testBasicRsa();
};
