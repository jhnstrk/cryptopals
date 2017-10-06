#pragma once

#include <QObject>

class TestSet7_55_wang: public QObject
{
    Q_OBJECT
private slots:
    void initTestCase() {}
    void cleanupTestCase() {}

    // Wangs attack on MD4
    void testChallenge55();
private:
    QVector<quint32> mPrimeFromM(const QVector<quint32> &input);
};
