#pragma once

#include <QObject>
#include <QTest>

class TestSet1: public QObject
{
    Q_OBJECT
private slots:
    void initTestCase();
    void cleanupTestCase();

    //Challenge 1
    void knownHexBase64_data();
    void knownHexBase64();


};
