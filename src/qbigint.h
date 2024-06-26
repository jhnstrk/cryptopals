#pragma once

#include <QMetaType>
#include <QPair>
#include <QVector>

// Forward declare.
class QDataStream;
class QDebug;

class QBigInt {

public:
    typedef quint32 WordType;
    typedef QVector<WordType> DataType;

    QBigInt();
    explicit QBigInt(quint32 value);
    explicit QBigInt(qint32 value);
    explicit QBigInt(quint64 value);
    explicit QBigInt(qint64 value);
    QBigInt(const QBigInt & other);
    ~QBigInt();

    static QBigInt fromString(const QString & s, int base);
    static QBigInt fromBigEndianBytes(const QByteArray & bytes);

    QBigInt & operator=(const QBigInt & other);
    QBigInt & operator=(qint32 i) { return this->operator =(QBigInt(i)); }
    QBigInt & operator=(quint32 i) { return this->operator =(QBigInt(i)); }
    QBigInt & operator=(qint64 i) { return this->operator =(QBigInt(i)); }
    QBigInt & operator=(quint64 i) { return this->operator =(QBigInt(i)); }

    QString toString(int base = 10) const;
    QByteArray toBigEndianBytes() const;

    inline bool isNegative() const { return m_sign; }
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

    inline const DataType & d() const { return m_d; }

    inline QBigInt & operator++() { return this->operator+=(1); }
    inline QBigInt & operator--() { return this->operator-=(1); }
    inline QBigInt operator++(int) { QBigInt tmp(*this); this->operator ++(); return tmp; }
    inline QBigInt operator--(int) { QBigInt tmp(*this); this->operator --(); return tmp; }

    QBigInt & operator+=(const QBigInt & other);
    QBigInt & operator-=(const QBigInt & other);
    QBigInt & operator+=(const WordType v);
    inline QBigInt & operator-=(const int v) { return this->operator-=(QBigInt(v)); }
    QBigInt & operator<<=(const unsigned int v);
    QBigInt & operator>>=(const unsigned int v);
    QBigInt & operator/=(const WordType v);
    QBigInt & operator*=(const WordType v);
    QBigInt & operator*=(const QBigInt & other);

    QBigInt & operator|=(const QBigInt & other);
    QBigInt & operator&=(const QBigInt & other);
    QBigInt & operator^=(const QBigInt & other);

    QBigInt & divRem(const WordType value, WordType &r);

    inline static QBigInt zero() { return QBigInt(0u); }
    inline static QBigInt one() { return QBigInt(1u); }
    inline static QBigInt minusOne() { return QBigInt(1u).negate(); }

    inline unsigned int flags() const { return m_flags; }
    inline void setFlags(unsigned int f) { m_flags = f; }

    //! Return (quotient, remainder)
    static QPair<QBigInt,QBigInt> divRem(const QBigInt & a, const QBigInt & b);

    //! Raise to power p
    QBigInt pow(const QBigInt & p) const;

    //! this to power p, mod m
    QBigInt powm(const QBigInt & p, const QBigInt & m) const;

    //! Return value cast to integer.
    //  @return current value cast to 64-bits.
    //   Will zero if this is not valid.
    //   Or the lower 64-bits if this is larger than the range of return type.
    qint64 toLongLong() const;
    quint64 toULongLong() const;

    //! return the modular multiplicative inverse under modulo m
    // i.e. return the x for which
    //    (a * x) mod m == 1.
    static QBigInt invmod(const QBigInt &a, const QBigInt & m);
    
    //! Return root and remainder.
    QPair<QBigInt,QBigInt> nthRootRem(unsigned int n) const;
private:
    explicit QBigInt(const DataType& d, bool sign);
    friend bool operator<(const QBigInt &a, const QBigInt &b);
    friend QPair<QBigInt,QBigInt> divRem(const QBigInt & a, const QBigInt & b);

    void remove_leading_zeros(); // Remove trailing zeros from d.

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
QBigInt operator|(const QBigInt & a, const QBigInt & b);
QBigInt operator&(const QBigInt & a, const QBigInt & b);
QBigInt operator^(const QBigInt & a, const QBigInt & b);

// Binary QBigInt, Word operators
QBigInt operator+(const QBigInt & a, const QBigInt::WordType v);
QBigInt operator-(const QBigInt & a, const QBigInt::WordType v);
QBigInt operator/(const QBigInt & a, const QBigInt::WordType v);
QBigInt operator*(const QBigInt & a, const QBigInt::WordType v);
QBigInt operator%(const QBigInt & a, const QBigInt::WordType v);

// Negate.
QBigInt operator-(const QBigInt & a);

// Bit shift
QBigInt operator<<(const QBigInt &a, unsigned int n);
QBigInt operator>>(const QBigInt &a, unsigned int n);

bool operator<(const QBigInt & a, const QBigInt & b);
bool operator<=(const QBigInt & a, const QBigInt & b);
bool operator>(const QBigInt & a, const QBigInt & b);
bool operator>=(const QBigInt & a, const QBigInt & b);
bool operator==(const QBigInt & a, const QBigInt & b);
inline bool operator!=(const QBigInt & a, const QBigInt & b) {
    return !(a == b);
}

bool operator==(const QBigInt & a, const QBigInt::WordType b);
inline bool operator!=(const QBigInt & a, const QBigInt::WordType b) {
    return !(a == b);
}

QBigInt operator*(const QBigInt & a, const QBigInt::WordType v);

template <typename T> QBigInt operator+(const QBigInt & a, const T & b) { return a + QBigInt(b); }
template <typename T> QBigInt operator+(const T & a, const QBigInt & b) { return QBigInt(a) + b; }
template <typename T> QBigInt operator-(const QBigInt & a, const T & b) { return a - QBigInt(b); }
template <typename T> QBigInt operator-(const T & a, const QBigInt & b) { return QBigInt(a) - b; }
template <typename T> QBigInt operator*(const QBigInt & a, const T & b) { return a * QBigInt(b); }
template <typename T> QBigInt operator*(const T & a, const QBigInt & b) { return QBigInt(a) * b; }
template <typename T> QBigInt operator/(const QBigInt & a, const T & b) { return a / QBigInt(b); }
template <typename T> QBigInt operator/(const T & a, const QBigInt & b) { return QBigInt(a) / b; }

template <typename T>  bool operator==(const QBigInt & a, const T & b) {    return a == QBigInt(b); }

template <typename T> bool operator!=(const QBigInt & a, const T & b) {     return !(a == b); }

QDebug operator<<(QDebug, const QBigInt & x);

uint qHash(const QBigInt & a, uint seed = 0);

Q_DECLARE_METATYPE(QBigInt)

QDataStream &operator<<(QDataStream &out, const QBigInt &obj);
QDataStream &operator>>(QDataStream &in, QBigInt &obj);
