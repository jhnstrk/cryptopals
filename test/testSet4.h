#pragma once

#include <QObject>
#include <QTest>

class TestSet4: public QObject
{
    Q_OBJECT
private slots:
    void initTestCase();
    void cleanupTestCase();

    // AES CTR, random access
    void testCtrEdit();
    void testChallenge25();

    // AES CTR: bit flipping
    void testChallenge26();

    // AES CBC: Recover key when key == iv.
    void testChallenge27();

    // 28: Sha1
    void testSha1_data();
    void testSha1();

    void testChallenge28();

    // Sha length extension attack
    void testChallenge29_1();
    void testChallenge29_2();

    // 30: Md4
    void testMd4_data();
    void testMd4();
};
