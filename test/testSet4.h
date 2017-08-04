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
};
