#pragma once

#include <QObject>

class TestSet6_bleichenbacher: public QObject
{
    Q_OBJECT
private slots:
    void initTestCase() {}
    void cleanupTestCase() {}

    // Basic tests of padding etc.
    void testPaddingOracle();

    // Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)
    void testChallenge47();
};
