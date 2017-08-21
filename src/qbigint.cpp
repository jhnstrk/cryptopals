#include "qbigint.h"

#include <QDataStream>
#include <QDebug>
#include <QHash>

namespace {
  class QBigIntMetaTypeInitializer {
      QBigIntMetaTypeInitializer() {
          qRegisterMetaType<QBigInt>();
      }
      static QBigIntMetaTypeInitializer m_obj;
  };

  QBigIntMetaTypeInitializer QBigIntMetaTypeInitializer::m_obj;

  QByteArray dump(const QBigInt::DataType &v) {
      QByteArray buffer;
      buffer.reserve(v.size() * (sizeof(QBigInt::WordType) * 2 + 2) + 2 );
      buffer.append('[');
      for (int i=0; i<v.size(); ++i) {
          if (i > 0) {
              buffer += ", ";
          }
          buffer += QByteArray::number(v.at(i),16);
      }
      buffer.append(']');
      return buffer;
  }

  QByteArray toHex(const QBigInt::DataType &v) {
      if (v.isEmpty()) {
          return "0x0";
      }

      QByteArray buffer;
      buffer.reserve(v.size() * (sizeof(QBigInt::WordType) * 2 + 2) + 2 );
      buffer.append("0x");
      buffer.append(QByteArray::number(v.back(),16));
      for (int i= v.size()-2; i>=0; --i) {
          QByteArray n = QByteArray::number(v.at(i),16);
          if (n.size() < int(sizeof(QBigInt::WordType)) * 2) {
              n.prepend(QByteArray(int(sizeof(QBigInt::WordType)) * 2 - n.size(),'0'));
          }
          buffer.append(n);
      }
      return buffer;
  }

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
      } else if (value >= QChar('A') && (value <= QChar('Z'))) {
          return value.unicode() - QChar('A').unicode() + 10;
      } else {
          return -1;
      }
  }

    const QBigInt::WordType Mask32 = 0xFFFFFFFFul;
    const unsigned int WordBytes = sizeof(QBigInt::WordType);
    const unsigned int WordBits = WordBytes * CHAR_BIT;
    typedef quint64 DWordType;

    enum Flags { SignFlag = 0x1, IsNull = 0x02, InValid = 0x04 };

    void shrink_vec(QBigInt::DataType & d) {
        int count = 0;
        for (int i=d.size()-1; i>=0 && d.at(i) == 0; --i) {
            ++count;
        }
        if (count != 0) {
            d.resize(d.size() - count);
        }
    }

    void unsigned_setBit(QBigInt::DataType & d, unsigned int n)
    {
        const unsigned int iw = n / WordBits;  // Word number
        const unsigned int ip = n % WordBits;  // bit position in word
        if (iw >= static_cast<unsigned int>(d.size())) {
            d.resize(iw + 1);
        }
        d[iw] |= (QBigInt::WordType(1) << ip);
    }

    bool unsigned_testBit(const QBigInt::DataType & d, const unsigned int n)
    {
        const unsigned int iw = n / WordBits;  // Word number
        const unsigned int ip = n % WordBits;  // bit position in word
        if (iw >= static_cast<unsigned int>(d.size())) {
            return false;
        }
        return ( ((d.at(iw) >> ip) & (QBigInt::WordType(1))) != 0);
    }

    // Compare magnitudes only, ignoring signs,
    // return -1, 0, or 1 for a<b, a==b, a>b
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

    // x += y
    void unsigned_add(QBigInt::DataType & x, const QBigInt::WordType & y)
    {
        if (y == 0) {
            return;
        }
        const int mx = std::max(x.size(), 1);
        x.resize(mx);  // zero extend.
        quint64 carry = y;
        for (int i=0; i<mx && (carry != 0); ++i) {
            carry += x.at(i);
            x[i] = carry & Mask32;
            carry >>= WordBits;
        }
        if (carry != 0) {
            x.append(carry & Mask32);
        }
    }

    // x - y, x must be bigger than y.
    void unsigned_subtract(QBigInt::DataType & v, const QBigInt::DataType & x, const QBigInt::DataType & y)
    {
        const int mx = x.size();

        v.resize(mx);

        quint64 borrow = 0;

        const int ySz = y.size();
        const QBigInt::WordType * yp = y.constData();
        const QBigInt::WordType * xp = x.constData();
        QBigInt::WordType * vp = v.data();
        for (int i=0; i<mx; ++i) {
            quint64 y_i = borrow;
            if (i < ySz) {
                y_i += yp[i];
            }
            quint64 x_i = xp[i];
            if (y_i > x_i) {
                borrow = 1;
                x_i += (quint64(1) << WordBits);
            } else {
                borrow = 0;
            }

            vp[i] = static_cast<QBigInt::WordType>(x_i - y_i);
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
            x.push_back(static_cast<QBigInt::WordType>(tmp));
        }
    }

    int highBitPosition(const QBigInt::WordType x)
    {
        for (unsigned int i = WordBits - 1; i>0; --i) {
            if ( (x & (QBigInt::WordType(1) << i) ) != 0) {
                return i;
            }
        }
        return ((x & 1u) != 0) ? 0 : -1;
    }
    
    int highBitPosition(const QBigInt::DataType & d)
    {
        if (d.isEmpty()) {
            return -1;
        }
        QBigInt::WordType highWord = d.back();
        return ::highBitPosition(highWord) + (d.size() - 1) * WordBits;
    }

    void setBytes(QBigInt::DataType & d, const unsigned char * const p, unsigned int n)
    {
        d.clear();
        d.reserve((n + WordBytes - 1)/ WordBytes);

        unsigned int i=n;  // i is the index AFTER the current one.
        for ( ;i > WordBytes; i-=WordBytes) {
            QBigInt::WordType back = 0;
            for (unsigned int j=0; j<WordBytes; ++j) {
                back |= QBigInt::WordType(p[i - 1 - j]) << (j*CHAR_BIT);
            }
            d.push_back(back);
        }
        if (i > 0) {
            QBigInt::WordType back = 0;
            for (unsigned int j=0; j<i; ++j) {
                back |= QBigInt::WordType(p[i - 1 - j]) << (j*CHAR_BIT);
            }
            d.push_back(back);
        }

        while (!d.isEmpty() && d.back() == 0u) {
            d.removeLast();
        }
    }

    void unsigned_lshift(QBigInt::DataType & d, const unsigned int v)
    {
        if (d.isEmpty()) {
            return;
        }
        const int n = v / WordBits;
        const unsigned int r = v % WordBits;
        const int initSize = d.size();

        const bool extra = (r != 0) && ( (d.back() >> (WordBits - r)) != 0 );

        d.resize(initSize + n + (extra ? 1 : 0));

        const int sz = d.size();

        QBigInt::WordType * d_ = d.data();
        if (n != 0) {
            // Do whole word shift
            for (int i=sz -1; i>=n; --i) {
                d_[i] = d_[i-n];
            }
            for (int i=n -1; i>=0; --i) {
                d_[i] = 0;
            }
        }

        if ( r != 0) {
            // Bit shift.
            QBigInt::WordType prev = 0;
            if ( n > 0 ) {
                prev = d_[n - 1];
            }
            for (int i=n; i<sz; ++i) {
                QBigInt::WordType high = (prev >> (WordBits - r));

                high |= (d_[i] << r);

                prev = d_[i];
                d_[i] = high;
            }
        }

    }

    // d <<= 1;  This is heavily used by divide; hence optimized.
    void unsigned_lshift_1(QBigInt::DataType & d)
    {
        if (d.isEmpty()) {
            return;
        }
        const int initSize = d.size();

        const bool extra = ( (d.back() >> (WordBits - 1)) != 0 );

        d.resize(initSize + (extra ? 1 : 0));

        const int sz = d.size();

        QBigInt::WordType * d_ = d.data();

        // Bit shift.
        QBigInt::WordType prev = 0;
        for (int i=0; i<sz; ++i) {
            QBigInt::WordType high = (prev >> (WordBits - 1));

            high |= (d_[i] << 1);

            prev = d_[i];
            d_[i] = high;
        }
    }

    void unsigned_rshift(QBigInt::DataType & d, unsigned int v)
    {
        const int n = v / WordBits;
        const unsigned int r = v % WordBits;
        const int initSize = d.size();
        if (n >= initSize) {
            d.clear();
            return;
        }

        if (n != 0) {
            // Word shift
            d = d.mid(n,initSize - n);
        }

        if ( r != 0) {
            // bit shift
            for (int i=0; i<d.size(); ++i) {
                QBigInt::WordType high = d.at(i);
                high >>= r;
                if (i + 1 < d.size()) {
                    high |= DWordType(d.at(i+1)) << (WordBits - r);
                }

                d[i] = high & Mask32;
            }

            if (d.back() == 0) {
                d.removeLast();
            }
        }

    }

    // The simplest method
    QPair<QBigInt::DataType, QBigInt::DataType> unsigned_divide_1(const QBigInt::DataType &num, const QBigInt::DataType &den)
    {
        const int highBitNum = highBitPosition(num);

        QBigInt::DataType q, r;

        for (int i = highBitNum; i >= 0; --i) {
            unsigned_lshift_1(r);              // r = r << 1
            if (unsigned_testBit(num,i)) {      // num_i ?
                unsigned_setBit(r,0);           // r_0 = 1
            }
            if ( unsigned_compare(r,den) >= 0 ) { // r >= den ?
                unsigned_subtract(r,r,den);    // r = r - den
                unsigned_setBit(q,i);
            }
        }

        typedef QPair<QBigInt::DataType, QBigInt::DataType>  ReturnType;
        return ReturnType(q, r);
    }


    // u -> u - (xv  << N)
    QBigInt::WordType subMulWord(const int j, QBigInt::DataType &u, const QBigInt::WordType x, const QBigInt::DataType &v)
    {
        if (x == 0) {
            return 0;
        }

        DWordType tmp = 0;
        const int u0 = u.size() - v.size() - j - 1;
        for (int i=0; i<v.size()+1; ++i) {
            if (i<v.size()) {
                tmp += DWordType(v.at(i)) * x;
            }
            DWordType mv_i = tmp & Mask32;

            tmp >>= WordBits;
            DWordType u_ix = u.at(i + u0);
            if (u_ix < mv_i) {
                ++tmp;  // borrow
                u_ix += (DWordType(1) << WordBits);
            }
            u[i + u0] = u_ix - mv_i;
        }

        return tmp;
    }

    QBigInt::WordType addBack(const int j, QBigInt::DataType &u, const QBigInt::DataType &v)
    {
        DWordType carry = 0;
        const int u0 = u.size() - v.size() - j - 1;

        for (int i=0; i<=v.size(); ++i) {
            if (i<v.size()) {
                carry += v.at(i);
            }
            carry += u.at(i + u0);
            u[i + u0] = carry & Mask32;
            carry >>= WordBits;
        }
        return carry;
    }
    // Knuth, Algrithm D method.
    // From The Art of Computer Programming, section 4.3.1
    QPair<QBigInt::DataType, QBigInt::DataType> unsigned_divide_k(const QBigInt::DataType &num, const QBigInt::DataType &den)
    {
        QBigInt::DataType u, v, q;
        u = num;
        v = den;

        // D1
        const unsigned int dShift = WordBits - 1 - highBitPosition(v.back());
        if (dShift != 0) {
            // Multiply u,v by d. d = 2**dShift
            unsigned_lshift(u,dShift);
            unsigned_lshift(v,dShift);
        }

        if (u.size() == num.size()) {
            u.push_back(0); // Create u_0
        }

        const int u0 = u.size() - 1;
        const int v1 = v.size() - 1;
        const int n = den.size();
        const int m = num.size() - n;
        //D2

        const QBigInt::WordType v_1 = v.at(v1);
        const QBigInt::WordType v_2 = v.at(v1-1);

        for (int j = 0; j<=m; ++j) {

            DWordType qHat = 0;

            // D3
            DWordType dwNext = (DWordType(u.at(u0 - j)) << WordBits) + DWordType(u.at(u0 - j - 1));
            if (u.at(u0 - j) == v_1) {
                qHat = Mask32;  // b - 1
            } else {
                qHat = dwNext / DWordType(v_1);
            }

            for (int iLoop = 0; iLoop <2; ++iLoop) {
                DWordType rhs =  (dwNext - qHat*v_1 );
                if ( (rhs >> WordBits) != 0) {
                    break;  // If it overflows, the test cannot be true.
                }
                if ( (v_2 * qHat) >
                      ( ( (rhs << WordBits)  + u.at(u0 -j - 2)) ) )
                {
                    --qHat;
                } else {
                    break;
                }
            }

            // D4: u = u - (qHat*v << N)
            const QBigInt::WordType carry = subMulWord(j,u,qHat,v);

            // D5: Test carry
            if(carry != 0) {

                // D6: u += (v << N)
                --qHat;
                const QBigInt::WordType carry2 = addBack(j,u,v);
                if (carry2 == 0) {
                    qDebug() << "Bad carry" << carry2;
                }
            }
            q.push_front(qHat);

            // D7...Loop
        }

        // D8: Unnormalize remainder
        QBigInt::DataType r = u.mid(0,v.size());
        unsigned_rshift(r,dShift);

        shrink_vec(q);
        shrink_vec(r);
        typedef QPair<QBigInt::DataType, QBigInt::DataType>  ReturnType;
        return ReturnType(q, r);
    }

    QPair<QBigInt::DataType, QBigInt::DataType> unsigned_divide(const QBigInt::DataType &num, const QBigInt::DataType &den)
    {
        typedef QPair<QBigInt::DataType, QBigInt::DataType>  ReturnType;
        if (den.size() == 1) {
            QBigInt::WordType v = den.at(0);
            QBigInt::WordType rW = 0;
            QBigInt::DataType q = num;
            unsigned_divide(q, v, rW);
            QBigInt::DataType r;
            if (rW != 0) {
                r.append(rW);
            }
            return ReturnType(q, r);
        }

        ReturnType t =  unsigned_divide_k(num,den);

        return t;
    }
}


QBigInt::QBigInt() : m_sign(false), m_flags(IsNull)
{

}

QBigInt QBigInt::fromString(const QString &s, int base)
{
    QBigInt tmp(QBigInt::zero());
    if (s.isEmpty()) {
        return tmp;
    }

    const int sz = s.size();
    bool negative = false;
    int i = 0;
    if (s.at(i) == QChar('-')) {
        negative = true;
        ++i;
    }

    for ( ;i<sz; ++i) {
        unsigned int v = charToValue(s.at(i));
        if (v < (unsigned int)base) {
            tmp *= base;
            tmp += v;
        } else {
            // Parse error really.
            tmp = QBigInt();
            break;
        }
    }

    if (negative && tmp.isValid()) {
        tmp.negate();
    }
    return tmp;
}

QBigInt QBigInt::fromBigEndianBytes(const QByteArray &bytes)
{
    QBigInt ret = QBigInt::zero();
    setBytes(ret.m_d, reinterpret_cast<const unsigned char *>(bytes.constData()), bytes.size());
    return ret;
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
    if (!this->isValid()) {
        return QString::fromLatin1("NaN");
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

QByteArray QBigInt::toBigEndianBytes() const
{
    QByteArray ret;
    ret.reserve(m_d.size()*WordBytes);
    for (int i=0; i<m_d.size() -1; ++i) {
        for (unsigned int j=0; j<WordBytes; ++j) {
            ret.push_back( static_cast<char>((m_d.at(i) >> (j*8)) & 0xFF) );
        }
    }
    if (!m_d.isEmpty()) {
        WordType back = m_d.back();
        const unsigned int last = (::highBitPosition(back) / CHAR_BIT ) + 1;
        for (unsigned int j=0; j<last; ++j) {
            ret.push_back( static_cast<char>((back >> (j*8)) & 0xFF) );
        }
    }
    std::reverse(ret.begin(), ret.end());
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

int QBigInt::highBitPosition() const
{
    if (!this->isValid()) {
        return -1;
    }
    return ::highBitPosition(m_d);
}

void QBigInt::setToZero()
{
    m_d.clear();
    m_flags = 0;
    m_sign = false;
}

void QBigInt::setBit(int ibit)
{
    if (ibit < 0) {
        return;
    }

    unsigned_setBit(m_d,static_cast<unsigned int>(ibit));
}

bool QBigInt::testBit(int ibit) const
{
    if (ibit < 0) {
        return false;
    }
    return unsigned_testBit(this->d(),static_cast<unsigned int>(ibit));
}


QBigInt &QBigInt::negate()
{
    this->m_sign = !this->m_sign;
    return *this;
}

QBigInt &QBigInt::operator+=(const WordType v) {
    if (this->isNegative()) {
        return this->operator+=(QBigInt(v));
    }
    unsigned_add(m_d, v);
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
    if (!this->isValid()) {
        return *this;
    }

    unsigned_lshift(m_d,v);

    return *this;
}

QBigInt &QBigInt::operator>>=(const unsigned int v)
{
    if (!this->isValid()) {
        return *this;
    }

    unsigned_rshift(m_d,v);

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

QBigInt::QBigInt(const QBigInt::DataType &d, bool sign) :
    m_d(d), m_sign(sign), m_flags(0)
{

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
    if (!a.isValid() || !b.isValid()) {
        return false;
    }
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

bool operator<=(const QBigInt &a, const QBigInt &b)
{
    return (a < b) || (a == b);
}

bool operator>(const QBigInt &a, const QBigInt &b)
{
    if (!a.isValid() || !b.isValid()) {
        return false;
    }
    if (a.isZero() && b.isZero()) {
        // Do not compare signs if zero
        return false;
    }

    if (!a.isNegative() && b.isNegative()) {
        return true;
    }

    if (!b.isNegative() && a.isNegative()) {
        return false;
    }

    // Same signs.
    const int cmp = unsigned_compare(a.d(), b.d());
    if (a.isNegative()) {
        return cmp == -1;
    } else {
        return cmp == 1;
    }
}

bool operator>=(const QBigInt &a, const QBigInt &b)
{
    return (a > b) || (a == b);
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

QBigInt operator/(const QBigInt &a, const QBigInt &b)
{
    return QBigInt::div(a,b).first;
}

QBigInt operator%(const QBigInt &a, const QBigInt &b)
{
    return QBigInt::div(a,b).second;
}

// static
QPair <QBigInt,QBigInt> QBigInt::div(const QBigInt &a, const QBigInt &b)
{
    typedef QPair <QBigInt,QBigInt> ReturnType;
    if (!a.isValid()) {
        return ReturnType(a,QBigInt());
    }

    if (!b.isValid()) {
        return ReturnType(b,QBigInt());
    }

    if (b.isZero()) {
        if (a.isZero()) {
            return ReturnType(QBigInt(),QBigInt());  // 0/0
        }
        return ReturnType(QBigInt(), QBigInt());  // Divide by zero.
    }

    if (a.isZero()) {
        return ReturnType(QBigInt::zero(),QBigInt::zero());  // 0/x
    }

    if (b.isOne()) {
        return ReturnType(a, QBigInt::zero());
    }

    switch (unsigned_compare(a.d(), b.d()) ) {
    case 0:
    // Equality |a| == |b|
        if (a.isNegative() == b.isNegative()) {
            return ReturnType(QBigInt::one(), QBigInt::zero());
        } else {
            return ReturnType(QBigInt::minusOne(), QBigInt::zero());
        }
    case -1:
        // |a| < |b|
        return ReturnType(QBigInt::zero(), a);
    case 1:
    default:
        // |b| < |a|  => Divide.
        break;
    }

    QPair< QBigInt::DataType, QBigInt::DataType > tmp = unsigned_divide(a.d(), b.d());

    if (a.isNegative() == b.isNegative()) {
        // A/B, -A / -B
        return ReturnType(QBigInt(tmp.first, false),  // quotient always positive
                          QBigInt(tmp.second, (!tmp.second.isEmpty()) && a.isNegative()));
    } else {
        // -A / B , A/-B
        if (tmp.second.isEmpty()) {
            // remainder is zero.
            return ReturnType(QBigInt(tmp.first, true), // quotient always negative
                              QBigInt::zero());
        } else {
            return ReturnType(QBigInt(tmp.first, true),  // quotient always negative
                              QBigInt(tmp.second, a.isNegative()));
        }

    }

    return ReturnType(QBigInt(), QBigInt());;
}

QBigInt QBigInt::exp(const QBigInt &p) const
{
    if (p.isNegative()) {
        qWarning() << "Cannot raise to negative power" << p;
        return QBigInt();
    }

    QBigInt ytmp = QBigInt::one();

    if (p.isZero()) {
        return ytmp;
    }

    QBigInt xtmp = *this;

    // Exponentiation by squaring.
    const int nb = p.highBitPosition();
    for (int i=0; i<nb; ++i) {
        if (p.testBit(i)) {
            ytmp *= xtmp;
        }
        xtmp *= xtmp;
    }
    return xtmp * ytmp;
}

QBigInt QBigInt::modExp(const QBigInt &p, const QBigInt &m) const
{
    if (p.isNegative()) {
        qWarning() << "Cannot raise to negative power" << p;
        return QBigInt();
    }

    QBigInt ytmp = QBigInt::one();

    if (p.isZero()) {
        return ytmp;
    }

    QBigInt xtmp = *this;

    // Exponentiation by squaring.
    const int nb = p.highBitPosition();
    for (int i=0; i<nb; ++i) {
        if (p.testBit(i)) {
            ytmp *= xtmp;
            ytmp = (ytmp % m);
        }
        xtmp *= xtmp;
        xtmp = (xtmp % m);
    }
    return (xtmp * ytmp) % m;
}
qint64 QBigInt::toLongLong() const
{
    qint64 v = this->toULongLong();
    if (this->isNegative()) {
        v = -v;
    }
    return v;
}

quint64 QBigInt::toULongLong() const
{
    if (!this->isValid()) {
        return 0;
    }
    quint64 v = 0;
    for (int i=0; i<m_d.size(); ++i) {
        if (i*WordBits >= 64) {
            break;
        }
        v |= (quint64)m_d.at(i) << (i*WordBits);
    }
    return v;
}

//static
QBigInt QBigInt::invmod(const QBigInt & a, const QBigInt &n)
{
    if (a.isZero() || !a.isValid() || n.isZero() || !n.isValid()) {
        qWarning() << "Not invertible";
        return QBigInt();
    }

    // The extended Euclidean Alogorithm under modulo arithmetic.
    QBigInt t = QBigInt::zero();
    QBigInt newt = QBigInt::one();
    QBigInt r = n;
    QBigInt newr = a;
    if (newr >= n) {
        newr = newr % n;
        if (newr.isZero()) {
            qWarning() << "Not invertible";
            return QBigInt();
        }
    }

    while (!newr.isZero()) {
        QPair<QBigInt, QBigInt> qr = div(r,newr);
        QBigInt tmp = t;
        t = newt % n;
        newt = tmp - qr.first * newt;
        r = newr;
        newr = qr.second;

        if (r.isNegative()) {
            qWarning() << "Not invertible" << r;
            return QBigInt();
        }

        if (t.isNegative()) {
            t += n;
        }
    }

    return t;
}

QPair<QBigInt, QBigInt> QBigInt::nthRootRem(unsigned int n) const
{
    typedef QPair<QBigInt, QBigInt> ReturnType;
    if (!this->isValid() || (n==0)) {
        return ReturnType();
    }
    if (this->isZero()) {
        return ReturnType(QBigInt::zero(), QBigInt::zero());
    }
    if (this->isOne()) {
        return ReturnType(QBigInt::one(), QBigInt::zero());
    }
    
    if (n == 1) {
        return ReturnType(*this, QBigInt::zero());
    }
    const int log2 = this->highBitPosition();
    QBigInt A = *this;
    if (A.isNegative()) {
        if ((n&1) == 0) {
            // Even root of a negative number => NaN.
            return ReturnType();
        }
        A.negate();
    }

    QBigInt a = A >> ((log2 + n - 1)/ n);

    bool rootFound = false;
    QBigInt rem;
    for (int i=0; i<log2 + 30; ++i) {
        QBigInt da = ( (A / a.exp(QBigInt(n-1)))  - a);
        da /= n;
        if (da.isZero()) {
            rem = A - a.exp(QBigInt(n));
            if (rem.isNegative()) {
                --a;
                rem = A - a.exp(QBigInt(n));
                if (!rem.isNegative()) {
                    rootFound = true;
                    break;
                }
            } else {
                QBigInt rem2 = A - (a + QBigInt::one()).exp(QBigInt(n));
                if (rem2.isNegative()) {
                    rootFound = true;
                    break;
                } else {
                    ++a;
                }
            }
        } else {
            a += da;
        }
    }

    if (!rootFound) {
        qWarning() << "Did not converge";
    }
    if (this->isNegative()) {
        a.negate();
        rem.negate();
    }
    return ReturnType(a, rem);
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

QDataStream &operator<<(QDataStream &out, const QBigInt &obj)
{
    unsigned char flags = obj.flags();
    if (obj.isNegative()) {
        flags |= SignFlag;
    }
    out << flags;
    if (obj.isValid()) {
        // Only write the array if object is valid.
        out << obj.toBigEndianBytes();
    }
    return out;
}

QDataStream &operator>>(QDataStream &in, QBigInt &obj)
{
    unsigned char flags = 0;
    QByteArray bytes;
    in >> flags;
    bool sign = (flags & SignFlag) != 0;
    flags &= (~(unsigned int)SignFlag); // Clear the sign flag.
    if (flags == 0) {
        in >> bytes;
        obj = QBigInt::fromBigEndianBytes(bytes);
    }
    if (sign) {
        obj.negate();
    }
    obj.setFlags(flags);
    return in;
}

QBigInt operator%(const QBigInt &a, const QBigInt::WordType v)
{
    return QBigInt::div(a,QBigInt(v)).second;
}
