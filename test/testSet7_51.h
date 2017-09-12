#pragma once

#include <QObject>

class TestSet7_51: public QObject
{
    Q_OBJECT
private slots:
    void initTestCase() {}
    void cleanupTestCase() {}

    // Compression oracle, stream cipher.
    void testChallenge51();

    // Compression oracle, block cipher (AES-CBC).
    void testChallenge51_cbc();
};
