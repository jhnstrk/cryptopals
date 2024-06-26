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

    // Break SRP
    void testChallenge37();

    // Break simple SRP
    void testChallenge38();

};
