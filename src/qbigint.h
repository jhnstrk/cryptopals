#pragma once

#include <QPair>
#include <QVector>

#include <QDebug>
class QBigInt {

public:
    typedef quint32 WordType;
    typedef QVector<WordType> DataType;

    QBigInt();
    QBigInt(const QString & s, int base);
    explicit QBigInt(const QByteArray & bytes);
    explicit QBigInt(quint32 value);
    explicit QBigInt(qint32 value);
    explicit QBigInt(quint64 value);
    explicit QBigInt(qint64 value);
    QBigInt(const QBigInt & other);
    ~QBigInt();

    QBigInt & operator=(const QBigInt & other);

    QString toString(int base = 10) const;
    QByteArray toLittleEndianBytes() const;

    bool isNegative() const { return m_sign; }
    bool isZero() const;
    bool isOne() const;
    bool isValid() const;

    //! Returns the position of the highest set bit.
    // returns -1 if this is zero or invalid.
    int highBitPosition() const;

    void setToZero();

    //! Set bit at given position to 1.
    //  Bit positions start from zero.
    void setBit(int ibit);
    //! Return true if bit at given position is set.
    //  Bit positions start from zero.
    bool testBit(int ibit) const;
    QBigInt & negate();

    const DataType & d() const { return m_d; }

    QBigInt & operator++() { return this->operator+=(1); }
    QBigInt & operator--() { return this->operator-=(1); }

    QBigInt & operator+=(const QBigInt & other);
    QBigInt & operator-=(const QBigInt & other);
    QBigInt & operator+=(const WordType v);
    QBigInt & operator-=(const int v) { return this->operator-=(QBigInt(v)); }
    QBigInt & operator<<=(const unsigned int v);
    QBigInt & operator>>=(const unsigned int v);
    QBigInt & operator/=(const WordType v);
    QBigInt & operator*=(const WordType v);
    QBigInt & operator*=(const QBigInt & other);
    QBigInt & div(const WordType value, WordType &r);

    static QBigInt zero() { return QBigInt(WordType(0)); }
    static QBigInt one() { return QBigInt(WordType(1)); }
    static QBigInt minusOne() { return QBigInt(WordType(1)).negate(); }

    unsigned int flags() const { return m_flags; }

    //! Return (quotient, remainder)
    static QPair<QBigInt,QBigInt> div(const QBigInt & a, const QBigInt & b);

    //! Raise to power p
    QBigInt exp(const QBigInt & p) const;

    //! this to power p, mod m
    QBigInt modExp(const QBigInt & p, const QBigInt & m) const;

private:
    explicit QBigInt(const DataType& d, bool sign);
    friend bool operator<(const QBigInt &a, const QBigInt &b);
    friend QPair<QBigInt,QBigInt> div(const QBigInt & a, const QBigInt & b);

    void shrink(); // Remove trailing zeros from d.

    // Follow openSsl and be little endian: least sig first.
    DataType m_d;
    bool m_sign;  // true => negative.
    unsigned int  m_flags;
};

// Binary QBigInt, QBigInt operators
QBigInt operator+(const QBigInt & a, const QBigInt & b);
QBigInt operator-(const QBigInt & a, const QBigInt & b);
QBigInt operator*(const QBigInt & a, const QBigInt & b);
QBigInt operator/(const QBigInt & a, const QBigInt & b);
QBigInt operator%(const QBigInt & a, const QBigInt & b);

// Binary QBigInt, Word operators
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

template <typename T>
bool operator==(const QBigInt & a, const T b) {
    return a == QBigInt(b);
}

template <typename T>
bool operator!=(const QBigInt & a, const T b) {
    return !(a == b);
}

QDebug operator<<(QDebug, const QBigInt & x);

uint qHash(const QBigInt & a, uint seed = 0);
