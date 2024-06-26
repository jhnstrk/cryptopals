#include "sha_1.h"
#include "bitsnbytes.h"
#include <QDebug>

// Implementation:
// Ref: Wikipedia

namespace {
    const int worklen = 80;
}

namespace qossl {

Sha1::Sha1() : m_count(0)
{
    this->reset();
}

Sha1::Sha1(quint32 a, quint32 b, quint32 c, quint32 d, quint32 e, quint64 count)
    :m_count(count)
{
    this->reset();
    m_h0 = a;
    m_h1 = b;
    m_h2 = c;
    m_h3 = d;
    m_h4 = e;

    m_count = count;
}

Sha1::~Sha1()
{

}

//static
QByteArray Sha1::hash(const QByteArray &data)
{
    Sha1 obj;
    obj.addData(data);
    return obj.finalize();
}

void Sha1::reset() {
    m_work.resize(worklen);

    m_h0 = 0x67452301u;
    m_h1 = 0xEFCDAB89u;
    m_h2 = 0x98BADCFEu;
    m_h3 = 0x10325476u;
    m_h4 = 0xC3D2E1F0u;

    m_count = 0;
    m_buffer.clear();
}

void Sha1::addData(const QByteArray &data)
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

QByteArray Sha1::finalize()
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
    m_buffer.append( uint64Be(m_count * CHAR_BIT) );
    this->addBlock(m_buffer,0);

    return uint32Be(m_h0)
            + uint32Be(m_h1)
            + uint32Be(m_h2)
            + uint32Be(m_h3)
            + uint32Be(m_h4);
}


void Sha1::addBlock(const QByteArray &data, int index)
{
    if (index + BlockSizeBytes > data.size() ) {
        qCritical() << "Bad block size" << data.size() << index;
    }

    const unsigned char * pdata = reinterpret_cast<const unsigned char *>(data.constData()) + index;
    // Populate work vector;
    for (int i=0; i<16; ++i) {
        m_work[i] = uint32_from_be(pdata + i*4);
    }

    for (int i = 16; i<worklen; ++i) {
        m_work[i] = leftrotate(m_work[i-3] ^ m_work[i-8] ^ m_work[i-14] ^ m_work[i-16], 1);
    }
    
    // Initialize hash value for this chunk:
    quint32 a = m_h0;
    quint32 b = m_h1;
    quint32 c = m_h2;
    quint32 d = m_h3;
    quint32 e = m_h4;
    
    for (int i = 0; i<worklen; ++i) {
        quint32 f,k;

        if (i < 20){
            f = (b & c) | ((~b) & d);
            k = 0x5A827999u;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1u;
        } else if ( i < 60 ) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDCu;
        } else { // if i < 80
            f = b ^ c ^ d;
            k = 0xCA62C1D6u;
        }

        const quint32 temp = leftrotate(a , 5) + f + e + k + m_work.at(i);
        e = d;
        d = c;
        c = leftrotate(b, 30);
        b = a;
        a = temp;
    }
    // Add this chunk's hash to result so far:
    m_h0 += a;
    m_h1 += b;
    m_h2 += c;
    m_h3 += d;
    m_h4 += e;
}

} // qossl
