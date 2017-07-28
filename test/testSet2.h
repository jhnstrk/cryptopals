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

    void testBreakEncrypionOracle2();
};

