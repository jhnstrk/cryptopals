#pragma once

#include <QObject>
#include <QTest>

class TestSet3: public QObject
{
    Q_OBJECT
private slots:
    void initTestCase();
    void cleanupTestCase();

    void testChallenge17();

    //Aes CTR
    void testChallenge18_data();
    void testChallenge18();

    //Aes CTR - fixed nonce
    void testChallenge19();

    // Aes CTR - fixed nonce 2
    void testChallenge20();

    // Mersenne twister
    void testChallenge21();

    // Finding seed of RNG
    void testChallenge22();

    // Inverting MT19937
    void testUnTemper();

    // Clone MT19937 by tapping its output.
    void testChallenge23();
};
