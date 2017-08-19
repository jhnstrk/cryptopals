#pragma once

#include <QObject>

class TestSet5: public QObject
{
    Q_OBJECT
private slots:
    void initTestCase();
    void cleanupTestCase();

    // Diffie Hellman
    void testChallenge33_1();
    void testChallenge33_2();

    // Diffie Hellman MITM
    void testChallenge34_1();
    void testChallenge34_2();

    // Diffie Hellman parameter tampering
    void testChallenge35();
    void testChallenge35_g_1(); // g=1
    void testChallenge35_g_p(); // g=p
    void testChallenge35_g_pm1(); // g=p-1

};
