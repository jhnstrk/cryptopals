#include "md4.h"

#include "bitsnbytes.h"
#include <QDebug>

// Implementation:
// Ref: https://tools.ietf.org/html/rfc1320

namespace {
    const int worklen = 16;

    // F(X,Y,Z) = XY v not(X) Z
    inline quint32 F(const quint32 x, const quint32 y, const quint32 z){
        return (x & y) | ( (~x) & z);
    }

    //G(X,Y,Z) = XY v XZ v YZ
    inline quint32 G(const quint32 x, const quint32 y, const quint32 z){
        return (x & y) | (x & z) | (y & z);
    }

    //H(X,Y,Z) = X xor Y xor Z
    inline quint32 H(const quint32 x, const quint32 y, const quint32 z){
        return x ^ y ^ z;
    }

    // Let [abcd k s] denote the operation
    //a = (a + F(b,c,d) + X[k]) <<< s.
    inline quint32 FF(const quint32 a, const quint32 b, const quint32 c, const quint32 d,
                const quint32 x_k, const unsigned int s)
    {
        return qossl::leftrotate((a + F(b,c,d) + x_k),s);
    }

    // Round2: Let [abcd k s] denote the operation
    // a = (a + G(b,c,d) + X[k] + 5A827999) <<< s.
    inline quint32 GG(const quint32 a, const quint32 b, const quint32 c, const quint32 d,
                const quint32 x_k, const unsigned int s)
    {
        return qossl::leftrotate((a + G(b,c,d) + x_k + 0x5A827999u),s);
    }

    //Round3: Let [abcd k s] denote the operation
    // a = (a + H(b,c,d) + X[k] + 6ED9EBA1) <<< s.
    inline quint32 HH(const quint32 a, const quint32 b, const quint32 c, const quint32 d,
                const quint32 x_k, const unsigned int s)
    {
        return qossl::leftrotate((a + H(b,c,d) + x_k + 0x6ED9EBA1u),s);
    }
}

namespace qossl {


Md4::Md4() : m_count(0)
{
    this->initialize();
}

Md4::Md4(quint32 a, quint32 b, quint32 c, quint32 d, quint64 count)
    :m_count(count)
{
    this->initialize();
    m_a = a;
    m_b = b;
    m_c = c;
    m_d = d;

    m_count = count;
}

Md4::~Md4()
{

}

//static
QByteArray Md4::hash(const QByteArray &data)
{
    Md4 obj;
    obj.addData(data);
    return obj.finalize();
}

void Md4::initialize() {
    m_work.resize(worklen);

    m_a = 0x67452301u;
    m_b = 0xEFCDAB89u;
    m_c = 0x98BADCFEu;
    m_d = 0x10325476u;

    m_count = 0;
}

void Md4::addData(const QByteArray &data)
{
    m_count += data.size();

    // less then a block
    if (m_buffer.size() + data.size() < BlockSizeBytes) {
        m_buffer.append(data);
        return;
    }

    int dataIndex = 0;
    if (!m_buffer.isEmpty()) {
        // fill buffer
        dataIndex = BlockSizeBytes - m_buffer.size();
        m_buffer.append(data.mid(0,dataIndex));
        this->addBlock(m_buffer,0);
    }

    int end = dataIndex + BlockSizeBytes;
    while (end <= data.size()) {
        this->addBlock(data, dataIndex);
        dataIndex = end;
        end += BlockSizeBytes;
    }

    m_buffer = data.mid(dataIndex);
}

QByteArray Md4::finalize()
{
    m_buffer.append((char)0x80);
    if (m_buffer.size() <= (BlockSizeBytes - 8) ) {
        m_buffer.append( QByteArray((BlockSizeBytes - 8) - m_buffer.size(),'\0'));
    } else {
        m_buffer.append( QByteArray(BlockSizeBytes - m_buffer.size(),'\0'));
        this->addBlock(m_buffer,0);
        m_buffer = QByteArray((BlockSizeBytes - 8),'\0');
    }

    // Message length in bits
    m_buffer.append( uint64Le(m_count * CHAR_BIT) );
    this->addBlock(m_buffer,0);

    return uint32Le(m_a)
            + uint32Le(m_b)
            + uint32Le(m_c)
            + uint32Le(m_d);
}


void Md4::addBlock(const QByteArray &data, int index)
{
    if (index + BlockSizeBytes > data.size() ) {
        qCritical() << "Bad block size" << data.size() << index;
    }

    const unsigned char * pdata = reinterpret_cast<const unsigned char *>(data.constData()) + index;

    // Initialize hash value for this chunk:
    quint32 a = m_a;
    quint32 b = m_b;
    quint32 c = m_c;
    quint32 d = m_d;

    /* Copy block i into X. */
    quint32 * X = m_work.data();
    // Populate work vector;
    for (int j=0; j<16; ++j) {
        X[j] = uint32_from_le(pdata + j*4);
    }

    /* Round 1. */
    /* Let [abcd k s] denote the operation
           a = (a + F(b,c,d) + X[k]) <<< s. */
    /* Do the following 16 operations. */
    a = FF(a,b,c,d, X[0],3);  d = FF(d,a,b,c, X[1],7);  c = FF(c,d,a,b, X[2],11);  b = FF(b,c,d,a, X[3],19);
    a = FF(a,b,c,d, X[4],3);  d = FF(d,a,b,c, X[5],7);  c = FF(c,d,a,b, X[6],11);  b = FF(b,c,d,a, X[7],19);
    a = FF(a,b,c,d, X[8],3);  d = FF(d,a,b,c, X[9],7);  c = FF(c,d,a,b,X[10],11);  b = FF(b,c,d,a,X[11],19);
    a = FF(a,b,c,d,X[12],3);  d = FF(d,a,b,c,X[13],7);  c = FF(c,d,a,b,X[14],11);  b = FF(b,c,d,a,X[15],19);

    /* Round 2. */
    /* Let [abcd k s] denote the operation
           a = (a + G(b,c,d) + X[k] + 5A827999) <<< s. */
    /* Do the following 16 operations. */
    a = GG(a,b,c,d, X[0],3);  d = GG(d,a,b,c, X[4],5);  c = GG(c,d,a,b, X[8],9);  b = GG(b,c,d,a,X[12],13);
    a = GG(a,b,c,d, X[1],3);  d = GG(d,a,b,c, X[5],5);  c = GG(c,d,a,b, X[9],9);  b = GG(b,c,d,a,X[13],13);
    a = GG(a,b,c,d, X[2],3);  d = GG(d,a,b,c, X[6],5);  c = GG(c,d,a,b,X[10],9);  b = GG(b,c,d,a,X[14],13);
    a = GG(a,b,c,d, X[3],3);  d = GG(d,a,b,c, X[7],5);  c = GG(c,d,a,b,X[11],9);  b = GG(b,c,d,a,X[15],13);

    /* Round 3. */
    /* Let [abcd k s] denote the operation
           a = (a + H(b,c,d) + X[k] + 6ED9EBA1) <<< s. */
    /* Do the following 16 operations. */
    a = HH(a,b,c,d, X[0],3);  d = HH(d,a,b,c, X[8],9);  c = HH(c,d,a,b,X[4],11);  b = HH(b,c,d,a,X[12],15);
    a = HH(a,b,c,d, X[2],3);  d = HH(d,a,b,c,X[10],9);  c = HH(c,d,a,b,X[6],11);  b = HH(b,c,d,a,X[14],15);
    a = HH(a,b,c,d, X[1],3);  d = HH(d,a,b,c, X[9],9);  c = HH(c,d,a,b,X[5],11);  b = HH(b,c,d,a,X[13],15);
    a = HH(a,b,c,d, X[3],3);  d = HH(d,a,b,c,X[11],9);  c = HH(c,d,a,b,X[7],11);  b = HH(b,c,d,a,X[15],15);

    /* Then perform the following additions. (That is, increment each
         of the four registers by the value it had before this block
         was started.) */

    // Add this chunk's hash to result so far:
    m_a += a;
    m_b += b;
    m_c += c;
    m_d += d;
}

} // qossl
