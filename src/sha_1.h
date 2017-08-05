#pragma once

#include <QByteArray>
#include <QVector>

namespace qossl {

class Sha1 {
public:
    Sha1();
    ~Sha1();

    static QByteArray hash(const QByteArray & data);

    void addData(const QByteArray & data);

    // Return hash
    QByteArray finalize();
private:

    void initialize();

    // Exactly 512 bits (64 bytes) are taken from data;
    void addBlock(const QByteArray & data, int index);

    QByteArray m_buffer;
    quint32 m_h0,m_h1,m_h2,m_h3,m_h4;

    QVector<quint32> m_work;
    quint64 m_count;
};

} // qossl
