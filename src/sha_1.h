#pragma once

#include <QByteArray>
#include <QVector>

namespace qossl {

class Sha1 {
public:
    static const int BlockSizeBytes = 512/8;  // 512 bits
    static const int HashSizeBytes = 20;

    Sha1();

    // Constructor for 'extension' attacks.
    Sha1(quint32 a, quint32 b, quint32 c,quint32 d,quint32 e, quint64 count);

    ~Sha1();

    static QByteArray hash(const QByteArray & data);

    void addData(const QByteArray & data);

    // Return hash
    QByteArray finalize();

    void reset();
private:

    // Exactly 512 bits (64 bytes) are taken from data;
    void addBlock(const QByteArray & data, int index);

    QByteArray m_buffer;
    quint32 m_h0,m_h1,m_h2,m_h3,m_h4;

    QVector<quint32> m_work;
    quint64 m_count;
};

} // qossl
