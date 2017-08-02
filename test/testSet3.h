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

};