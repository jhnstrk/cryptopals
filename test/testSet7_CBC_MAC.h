#pragma once

#include <QObject>

class TestSet7_CBC_MAC: public QObject
{
    Q_OBJECT
private slots:
    void initTestCase() {}
    void cleanupTestCase() {}

    // CBC-MAC
    void testChallenge49_basic();
    void testChallenge49();

};
