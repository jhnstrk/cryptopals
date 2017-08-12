#include "qbigint.h"

#include <QDebug>
#include <QHash>

namespace {
  char valueToChar(unsigned int value)
  {
      if (value < 10) {
          return (char)value + '0';
      } else if (value < 37) {
          return (char)(value - 10) + 'a';
      } else {
          return '?'; // overflow.
      }
  }

  unsigned int charToValue( QChar value )
  {
      if (value >= QChar('0') && (value <= QChar('9'))) {
          return value.unicode() - QChar('0').unicode();
      } else if (value >= QChar('a') && (value <= QChar('z'))) {
          return value.unicode() - QChar('a').unicode() + 10;
      } else {
          return -1;
      }
  }

    const QBigInt::WordType Mask32 = 0xFFFFFFFFul;
    const unsigned int WordBytes = sizeof(QBigInt::WordType);
    const unsigned int WordBits = WordBytes * CHAR_BIT;
    typedef quint64 DWordType;

    enum Flags { IsNull = 0x01, InValid = 0x02 };

    void shrink_vec(QBigInt::DataType & v) {
        while ((v.size()) > 0 && (v.back() == 0)) {
            v.removeLast();
        }
    }

    // Compare magnitudes only, ignoring signs,
    // return -1, 0, or 1 for a<b, a==b, b<a
    int unsigned_compare(const QBigInt::DataType & x, const QBigInt::DataType & y)
    {
        // Sign is same
        if (x.size() < y.size()) {
            return -1;
        }
        if (y.size() < x.size()) {
            return 1;
        }

        //same size.
        // compare largest first.
        for (int i=x.size()-1; i>=0; --i) {
            if (x.at(i) < y.at(i)) {
                return -1;
            }
            if (y.at(i) < x.at(i)) {
                return 1;
            }
        }
        // Equal.
        return 0;
    }

    bool unsigned_lessthan(const QBigInt::DataType & x, const QBigInt::DataType & y)
    {
        return (unsigned_compare(x,y) == -1);
    }

    // x + y, store in v. v may alias x or y.
    void unsigned_add(QBigInt::DataType & v, const QBigInt::DataType & x, const QBigInt::DataType & y)
    {
        const int mx = std::max(x.size(), y.size());

        quint64 carry = 0;
        v.resize(mx);  // zero extend.
        for (int i=0; i<mx; ++i) {
            if (i < y.size()) {
                carry += y.at(i);
            }
            carry += x.at(i);
            v[i] = carry & Mask32;
            carry >>= WordBits;
        }
        if (carry != 0) {
            v.append(carry & Mask32);
        }
    }

    // x - y, x must be bigger than y.
    void unsigned_subtract(QBigInt::DataType & v, const QBigInt::DataType & x, const QBigInt::DataType & y)
    {
        const int mx = x.size();

        v.resize(mx);

        quint64 borrow = 0;

        for (int i=0; i<mx; ++i) {
            quint64 y_i = borrow;
            if (i < y.size()) {
                y_i += y.at(i);
            }
            quint64 x_i = x.at(i);
            if (y_i > x_i) {
                borrow = 1;
                x_i += (quint64(1) << WordBits);
            } else {
                borrow = 0;
            }

            v[i] = x_i - y_i;
        }

        shrink_vec(v);
    }

    // divide by value
    void unsigned_divide(QBigInt::DataType & x,
                                      const QBigInt::WordType value, QBigInt::WordType & remainder)
    {
        DWordType tmp = 0;
        typedef QBigInt::WordType WordType;
        for (int i = x.size()-1; i>=0; --i) {
            tmp <<= WordBits;
            tmp += x.at(i);
            const DWordType x_div = tmp / value;
            tmp = tmp % value;
            x[i] = static_cast<WordType>(x_div);
        }
        if (x.back() == 0) {
            x.removeLast();
        }

        remainder = static_cast<WordType>(tmp);
    }

    // multiply by value
    void unsigned_multiply(QBigInt::DataType & x,
                                      const QBigInt::WordType value)
    {
        DWordType tmp = 0;
        for (int i=0; i<x.size(); ++i) {
            tmp += DWordType(x.at(i)) * value;
            x[i] = tmp & Mask32;
            tmp >>= WordBits;
        }
        if (tmp != 0) {
            x.push_back(tmp);
        }
    }

}


QBigInt::QBigInt() : m_sign(false), m_flags(IsNull)
{

}

QBigInt::QBigInt(const QString &s, int base) : m_sign(false), m_flags(IsNull)
{
    // TODO
    if (s.isEmpty()) {
        return;
    }

    const int sz = s.size();
    QBigInt tmp(QBigInt::zero());
    int i = 0;
    if (s.at(i) == QChar('-')) {
        tmp.negate();
        ++i;
    }

    for ( ;i<sz; ++i) {
        unsigned int v = charToValue(s.at(i));
        if (v < (unsigned int)base) {
            tmp *= base;
            tmp += v;
        } else {
            // Parse error really.
            break;
        }
    }
    this->operator =(tmp);
}

QBigInt::QBigInt(WordType value) :    m_sign(false), m_flags(0)
{
    if (value != 0){
        m_d.append(value);
    }
}

QBigInt::QBigInt(qint32 value) : m_sign(value < 0), m_flags(0)
{
    if (m_sign) {
        m_d.append(static_cast<WordType>(-value));
    } else if (value != 0) {
        m_d.append(static_cast<WordType>(value));
    }
}

QBigInt::QBigInt(quint64 value):      m_sign(false), m_flags(0)
{
    if (value != 0) {
        m_d.append(static_cast<WordType>(value & Mask32));
        WordType t = static_cast<WordType>((value >> 32) & Mask32);
        if (t != 0) {
            m_d.append(t);
        }
    }
}

QBigInt::QBigInt(qint64 value):      m_sign(value < 0), m_flags(0)
{
    if (m_sign) {
        value = -value;
    }
    if (value != 0) {
        m_d.append(static_cast<WordType>(value & Mask32));
        WordType t = static_cast<WordType>((value >> 32) & Mask32);
        if (t != 0) {
            m_d.append(t);
        }
    }
}

QBigInt::QBigInt(const QBigInt &other) :
    m_d(other.m_d),
    m_sign(other.m_sign),
    m_flags(other.m_flags)
{

}

QBigInt::~QBigInt()
{

}

QBigInt &QBigInt::operator=(const QBigInt &other)
{
    m_d = other.m_d;
    m_sign = other.m_sign;
    m_flags = other.m_flags;
    return *this;
}

QString QBigInt::toString(int base) const
{
    if (this->isZero()) {
        return QString::fromLatin1("0");
    }
    if ((base < 2) || (base > 36)) {
        qCritical() << "Invalid base" << base;
        return QString();
    }
    QBigInt t(*this);
    QString ret;
    while (!t.isZero()) {
        WordType remainder;
        t = t.div( (WordType)base, remainder);
        ret.push_front( valueToChar(remainder) );
    }
    if (this->isNegative()) {
        ret.push_front(QLatin1Char('-'));
    }
    return ret;
}

bool QBigInt::isZero() const
{
    return (m_flags == 0) && m_d.isEmpty();
}

bool QBigInt::isOne() const
{
    return (m_flags == 0) && (!this->isNegative()) && (m_d.size() == 1) && (m_d.at(0) == 1);
}

bool QBigInt::isValid() const
{
    return (m_flags == 0);
}

void QBigInt::setToZero()
{
    m_d.clear();
    m_flags = 0;
    m_sign = false;
}


QBigInt &QBigInt::negate()
{
    this->m_sign = !this->m_sign;
    return *this;
}

QBigInt & QBigInt::operator+=(const QBigInt &other)
{
    if (this->isNegative() == other.isNegative()) {
        // No sign changes.
        unsigned_add(m_d, this->m_d, other.d());
    } else if (this->isNegative()) {
        // other is not negative.
        // -a + b => b - a
        if (unsigned_lessthan(other.d(), this->d())) {
            //  -(a-b)
            unsigned_subtract(m_d, this->d(), other.d());
        } else {
            // b - a
            unsigned_subtract(m_d, other.d(), this->d() );
            this->negate();
        }
    } else {
        // other is negative, we are not.
        // a + -b => a - b
        if (unsigned_lessthan(this->d(), other.d())) {
            //  -(b-a)
            unsigned_subtract(m_d, other.d(), this->d());
            this->negate();
        } else {
            // a - b
            unsigned_subtract(m_d, this->d(), other.d() );
        }
    }
    return *this;
}

QBigInt & QBigInt::operator-=(const QBigInt &other)
{
    if (this->isNegative() && !other.isNegative()) {
        // -a - b => -(a+b)
        unsigned_add(m_d, this->m_d, other.d());
    } else if (!this->isNegative() && other.isNegative()) {
        //  a - -b => (a+b)
        unsigned_add(m_d, this->m_d, other.d());
        return *this;
    } else if (this->isNegative()) {
        // other is negative
        // -a - -b => b - a
        if (unsigned_lessthan(other.d(),this->d())) {
            //  -(a-b)
            unsigned_subtract(m_d, this->d(), other.d());
        } else {
            // b - a
            unsigned_subtract(m_d, other.d(), this->d() );
            this->negate();
        }
    } else {
        // other is positive, as are we.
        // a - b => a - b
        if (unsigned_lessthan(this->d(), other.d())) {
            //  -(b-a)
            unsigned_subtract(m_d, other.d(), this->d());
            this->negate();
        } else {
            // a - b
            unsigned_subtract(m_d, this->d(), other.d() );
        }
    }
    return *this;
}

QBigInt &QBigInt::operator<<=(const unsigned int v)
{
    if (this->isZero() || !this->isValid()) {
        return *this;
    }

    const int n = v / WordBits;
    const unsigned int r = v % WordBits;
    const int initSize = m_d.size();

    m_d.resize(initSize + n + (r != 0 ? 1 : 0));
    const int sz = m_d.size();

    if (n != 0) {
        // Do whole word shift
        for (int i=sz -1; i>=n; --i) {
            m_d[i] = m_d.at(i-n);
        }
        for (int i=n -1; i>=0; --i) {
            m_d[i] = 0;
        }
    }

    if ( r != 0) {
        // Bit shift.
        for (int i=sz -1; i>=n; --i) {
            WordType high;
            if (i - 1 >= 0) {
                high = (DWordType(m_d.at(i - 1)) >> (WordBits - r));
            } else {
                high = 0;
            }

            high |= (DWordType(m_d.at(i)) << r);

            m_d[i] = high & Mask32;
        }
        if (m_d.back() == 0) {
            m_d.removeLast();
        }
    }

    return *this;
}

QBigInt &QBigInt::operator>>=(const unsigned int v)
{
    if (this->isZero() || !this->isValid()) {
        return *this;
    }

    const int n = v / WordBits;
    const unsigned int r = v % WordBits;
    const int initSize = m_d.size();
    if (n >= initSize) {
        this->setToZero();
        return *this;
    }

    if (n != 0) {
        // Word shift
        m_d = m_d.mid(n,initSize - n);
    }

    if ( r != 0) {
        // bit shift
        for (int i=0; i<m_d.size(); ++i) {
            WordType high = m_d.at(i);
            high >>= r;
            if (i + 1 < m_d.size()) {
                high |= DWordType(m_d.at(i+1)) << (WordBits - r);
            }

            m_d[i] = high & Mask32;
        }

        if (m_d.back() == 0) {
            m_d.removeLast();
        }
    }

    return *this;
}

QBigInt &QBigInt::operator/=(const QBigInt::WordType value)
{
    QBigInt::WordType r;
    return this->div(value, r);
}

QBigInt &QBigInt::operator*=(const QBigInt::WordType v)
{
    if (this->isZero() || !this->isValid()) {
        return *this;
    }

    unsigned_multiply(m_d, v);
    return *this;
}

QBigInt &QBigInt::operator*=(const QBigInt &other)
{
    this->operator=(*this * other);
    return *this;
}

QBigInt &QBigInt::div(const QBigInt::WordType value, QBigInt::WordType & r)
{
    if (this->isZero()) {
        r = 0;
        if (value == 0) {
            qCritical() << "0/0";
            this->m_d.clear();
            this->m_flags = InValid;
            return *this;
        }
        return *this;
    }

    if (!this->isValid()) {
        r = 0;
        return *this;
    }

    if (value == 1) {
        r = 0;
        return *this;
    }
    unsigned_divide(m_d, value, r);
    return *this;
}

void QBigInt::shrink()
{
    shrink_vec(m_d);
}

bool operator==(const QBigInt &a, const QBigInt &b)
{
    if (a.isZero() && b.isZero()) {
        // Do not compare signs if zero
        return true;
    }

    //Sign compare.
    if (a.isNegative() != b.isNegative()) {
        return false;
    }

    return (a.d() == b.d()) ;
}

bool operator==(const QBigInt & a, const QBigInt::WordType b)
{
    return a.isValid() && (!a.isNegative())
            && ( ( (a.d().size() == 1) && (a.d().first() == b) )
                  || (a.isZero() && (b == 0)));
}

bool operator<(const QBigInt &a, const QBigInt &b)
{
    if (a.isZero() && b.isZero()) {
        // Do not compare signs if zero
        return false;
    }

    if (a.isNegative() && !b.isNegative()) {
        return true;
    }

    if (b.isNegative() && !a.isNegative()) {
        return false;
    }

    // Same signs.
    const int cmp = unsigned_compare(a.d(), b.d());
    if (a.isNegative()) {
        return cmp == 1;
    } else {
        return cmp == -1;
    }
}

QBigInt operator+(const QBigInt &a, const QBigInt &b)
{
    QBigInt ret(a);
    ret += b;
    return ret;
}

QBigInt operator-(const QBigInt &a, const QBigInt &b)
{
    QBigInt ret(a);
    ret -= b;
    return ret;
}

QBigInt operator<<(const QBigInt &a, unsigned int n)
{
    QBigInt ret(a);
    ret <<= n;
    return ret;
}

QBigInt operator>>(const QBigInt &a, unsigned int n)
{
    QBigInt ret(a);
    ret >>= n;
    return ret;
}

QDebug operator<<(QDebug dbg, const QBigInt &x)
{
    dbg << x.toString();
    return dbg;
}

QBigInt operator-(const QBigInt &a)
{
    QBigInt ret(a);
    return ret.negate();
}

uint qHash(const QBigInt &a, uint seed)
{
    uint ret = seed;
    ret = qHash(a.d().size(), ret);
    foreach (const QBigInt::WordType & item, a.d()) {
        ret = qHash(item, ret);
    }
    ret = qHash(a.isNegative(), ret);
    ret = qHash(a.flags(), ret);
    return ret;
}

QBigInt operator/(const QBigInt &a, const QBigInt::WordType v)
{
    QBigInt ret(a);
    ret /= v;
    return ret;
}

QBigInt operator*(const QBigInt &a, const QBigInt::WordType v)
{
    QBigInt ret(a);
    ret *= v;
    return ret;
}

QBigInt operator*(const QBigInt &a, const QBigInt &b)
{
    if (!a.isValid()) {
        return a;
    }

    if (!b.isValid()) {
        return b;
    }

    if (a.isZero() || b.isOne()) {
        return a;
    }

    if (a.isOne()) {
        return b;
    }

    QBigInt result = QBigInt::zero();
    for (int i = 0; i<b.d().size(); ++i) {
        result += (a * b.d().at(i)) << (unsigned int)(i * WordBits);
    }
    if (b.isNegative()) {
        result.negate();
    }

    return result;
}

QBigInt operator+(const QBigInt &a, const QBigInt::WordType v)
{
    QBigInt ret(a);
    ret += QBigInt(v);
    return ret;
}

QBigInt operator-(const QBigInt &a, const QBigInt::WordType v)
{
    QBigInt ret(a);
    ret -= QBigInt(v);
    return ret;
}
