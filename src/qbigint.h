#pragma once

#include <QVector>

#include <QDebug>
class QBigInt {

public:
    typedef quint32 WordType;
    typedef QVector<WordType> DataType;

    QBigInt();
    QBigInt(const QString & s, int base);
    QBigInt(quint32 value);
    QBigInt(qint32 value);
    QBigInt(quint64 value);
    QBigInt(qint64 value);
    QBigInt(const QBigInt & other);
    ~QBigInt();

    QString toString(int base = 10) const;

    bool isNegative() const { return m_sign; }
    bool isZero() const;
    bool isValid() const;

    void setToZero();

    // devide by value, return *this.
    QBigInt & divide(const WordType value, WordType & remainder);
    QBigInt & negate();

    const DataType & d() const { return m_d; }

    QBigInt & operator+=(const QBigInt & other);
    QBigInt & operator-=(const QBigInt & other);
    QBigInt & operator<<=(const unsigned int v);
    QBigInt & operator>>=(const unsigned int v);

    static QBigInt zero() { return QBigInt(WordType(0)); }
    static QBigInt one() { return QBigInt(WordType(1)); }
    static QBigInt minus_one() { return QBigInt(WordType(1)).negate(); }

private:

    friend bool operator<(const QBigInt &a, const QBigInt &b);

    void shrink(); // Remove trailing zeros from d.

    // Follow openSsl and be little endian: least sig first.
    DataType m_d;
    bool m_sign;  // true => negative.
    unsigned int  m_flags;
};

QBigInt operator+(const QBigInt & a, const QBigInt & b);
QBigInt operator-(const QBigInt & a, const QBigInt & b);
QBigInt operator-(const QBigInt & a);
QBigInt operator<<(const QBigInt &a, unsigned int n);
QBigInt operator>>(const QBigInt &a, unsigned int n);

bool operator<(const QBigInt & a, const QBigInt & b);
bool operator==(const QBigInt & a, const QBigInt & b);
bool operator!=(const QBigInt & a, const QBigInt & b) {
    return !(a == b);
}

bool operator==(const QBigInt & a, const QBigInt::WordType b);
bool operator!=(const QBigInt & a, const QBigInt::WordType b) {
    return !(a == b);
}

QDebug operator<<(QDebug, const QBigInt & x);

