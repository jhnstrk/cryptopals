#pragma once

#include <QObject>
#include <QTest>

class TestSet1: public QObject
{
    Q_OBJECT
private slots:
    void initTestCase();
    void cleanupTestCase();

    //Challenge 1: Base64
    void knownHexBase64_data();
    void knownHexBase64();

    //Challenge 2: XOR
    void testXor_data();
    void testXor();

    //Challenge 3: Crack single-char xor.
    void testXorCrack();

    // Challenge 4: Find encrypted string.
    void testXorCrack2();
};
