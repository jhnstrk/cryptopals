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
};
