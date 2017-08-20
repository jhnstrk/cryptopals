#pragma once

#include <QObject>

class TestSet5_Srp: public QObject
{
    Q_OBJECT
private slots:
    void initTestCase();
    void cleanupTestCase();

    // Secure Remote Password
    void testChallenge36();
};
