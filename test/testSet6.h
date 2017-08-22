#pragma once

#include <QObject>

class TestSet6: public QObject
{
    Q_OBJECT
private slots:
    void initTestCase() {}
    void cleanupTestCase() {}

    // Rsa - Implement unpadded message recovery oracle
    void testChallenge41();

    // Rsa - Bleichenbacher's e=3 RSA Attack
    void testChallenge42();
};
