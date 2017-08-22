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

};
