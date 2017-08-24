#pragma once

#include <QObject>

class TestSet6_Dsa: public QObject
{
    Q_OBJECT
private slots:
    void initTestCase() {}
    void cleanupTestCase() {}

    // Challenge 43
    // Dsa - Implement DSA
    void testBasicDsa();

    // Key recovery from nonce.
    void testChallenge43();

    // repeated nonce - recovery of nonce.
    void testChallenge44();
};
