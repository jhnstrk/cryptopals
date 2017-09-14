#pragma once

#include <QObject>

class TestSet7_52: public QObject
{
    Q_OBJECT
private slots:
    void initTestCase() {}
    void cleanupTestCase() {}

    // Iterated hash functions
    void testChallenge52();

};
