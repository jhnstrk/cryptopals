#pragma once

#include <QObject>
#include <QTest>

class TestSet2: public QObject
{
    Q_OBJECT
private slots:
    void initTestCase();
    void cleanupTestCase();

    //Challenge 1: PKCS#7
    void testPkcs7Pad_data();
    void testPkcs7Pad();
};
