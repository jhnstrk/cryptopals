#pragma once

#include <QByteArray>

// Various bit and byte utilities.
namespace qossl {

//! extract bit endian v from bytestream
quint32 uint32_from_be(const unsigned char * p)
{
    return (((quint32)p[0]) << 24) |
            (((quint32)p[1]) << 16) |
            (((quint32)p[2]) << 8) |
            (((quint32)p[3]));
}

//! Cyclic rotation of 32-bit uint.
//  NOT safe if n == 0 || n >= 32 because oob shifts are compiler-dependent.
quint32 leftrotate(quint32 v, unsigned int n){
    return (v << n) | (v >> (32-n));
}

//! The byte representation of unsigned 64-bit int as Big-Endian.
QByteArray uint64Be( const quint64 v)
{
    QByteArray ret(8,'\0');
    char * pdata = ret.data();
    pdata[0] = static_cast<char>((v >> 56) & 0xFF);
    pdata[1] = static_cast<char>((v >> 48) & 0xFF);
    pdata[2] = static_cast<char>((v >> 40) & 0xFF);
    pdata[3] = static_cast<char>((v >> 32) & 0xFF);
    pdata[4] = static_cast<char>((v >> 24) & 0xFF);
    pdata[5] = static_cast<char>((v >> 16) & 0xFF);
    pdata[6] = static_cast<char>((v >> 8) & 0xFF);
    pdata[7] = static_cast<char>(v & 0xFF);
    return ret;
}

//! The byte representation of unsigned 32-bit int as Big-Endian.
QByteArray uint32Be( const quint32 v)
{
    QByteArray ret(4,'\0');
    char * pdata = ret.data();
    pdata[0] = static_cast<char>((v >> 24) & 0xFF);
    pdata[1] = static_cast<char>((v >> 16) & 0xFF);
    pdata[2] = static_cast<char>((v >> 8) & 0xFF);
    pdata[3] = static_cast<char>(v & 0xFF);
    return ret;
}
}
