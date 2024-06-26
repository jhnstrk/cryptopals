#pragma once

#include <QObject>
#include <QTest>

#include <utils.h>

class TestSet2: public QObject
{
    Q_OBJECT
private slots:
    void initTestCase();
    void cleanupTestCase();

    //Challenge 9: PKCS#7
    void testPkcs7Pad_data();
    void testPkcs7Pad();

    // Challenge 10: AES CBC
    void testAesCbcDecrypt_data();
    void testAesCbcDecrypt();

    void testAesCbcEncrypt_data();
    void testAesCbcEncrypt();

    //Challenge 11
    void testEncryptionOracle_data();
    void testEncryptionOracle();

    // Challenge 12
    void testBreakEncrypionOracle2();

    // Challenge 13
    void testChallenge13();

    // Challenge 14
    void testChallenge14();

    // Challenge 15: Pkcs7 2.
    void testChallenge15_data();
    void testChallenge15();

    // Challenge 16: AES CBC
    void testChallenge16();

};

