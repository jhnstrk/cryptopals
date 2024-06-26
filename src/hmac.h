#pragma once

class QByteArray;

namespace qossl {

QByteArray hmacSha1(const QByteArray & key, const QByteArray & data );
QByteArray hmacSha256(const QByteArray & key, const QByteArray & data );

}
