#pragma once

#include <QByteArray>
#include <QVector>

namespace qossl {

class Md4 {
public:
    static const int BlockSizeBytes = 512/8;  // 512 bits, or 64 bytes

    Md4();

    // Constructor for 'extension' attacks.
    Md4(quint32 a, quint32 b, quint32 c,quint32 d, quint64 count);

    ~Md4();

    static QByteArray hash(const QByteArray & data);

    void addData(const QByteArray & data);

    // Return hash
    QByteArray finalize();
private:

    void initialize();

    // Exactly 512 bits (64 bytes) are taken from data;
    void addBlock(const QByteArray & data, int index);

    QByteArray m_buffer;
    quint32 m_a,m_b,m_c,m_d;

    QVector<quint32> m_work;
    quint64 m_count;
};

} // qossl
