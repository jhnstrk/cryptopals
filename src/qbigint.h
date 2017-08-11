#pragma once

#include <QVector>

#include <QDebug>
class QBigInt {

public:
    typedef quint32 WordType;
    typedef QVector<WordType> DataType;

    QBigInt();
    QBigInt(const QString & s, int base);
    explicit QBigInt(quint32 value);
    explicit QBigInt(qint32 value);
    explicit QBigInt(quint64 value);
    explicit QBigInt(qint64 value);
    QBigInt(const QBigInt & other);
    ~QBigInt();

    QBigInt & operator=(const QBigInt & other);

    QString toString(int base = 10) const;

    bool isNegative() const { return m_sign; }
    bool isZero() const;
    bool isOne() const;
    bool isValid() const;

    void setToZero();

    QBigInt & negate();

    const DataType & d() const { return m_d; }

    QBigInt & operator+=(const QBigInt & other);
    QBigInt & operator-=(const QBigInt & other);
    QBigInt & operator+=(const qint32 & v) { return this->operator+=(QBigInt(v)); }
    QBigInt & operator-=(const qint32 & v) { return this->operator-=(QBigInt(v)); }
    QBigInt & operator<<=(const unsigned int v);
    QBigInt & operator>>=(const unsigned int v);
    QBigInt & operator/=(const WordType v);
    QBigInt & operator*=(const WordType v);
    QBigInt & operator*=(const QBigInt & other);
    QBigInt & div(const WordType value, WordType &r);

    static QBigInt zero() { return QBigInt(WordType(0)); }
    static QBigInt one() { return QBigInt(WordType(1)); }
    static QBigInt minus_one() { return QBigInt(WordType(1)).negate(); }

    unsigned int flags() const { return m_flags; }
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
QBigInt operator*(const QBigInt & a, const QBigInt & b);
QBigInt operator/(const QBigInt & a, const QBigInt & b);
QBigInt operator+(const QBigInt & a, const QBigInt::WordType v);
QBigInt operator-(const QBigInt & a, const QBigInt::WordType v);
QBigInt operator/(const QBigInt & a, const QBigInt::WordType v);
QBigInt operator*(const QBigInt & a, const QBigInt::WordType v);

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

uint qHash(const QBigInt & a, uint seed = 0);
