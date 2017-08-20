#include "hmac.h"

#include "sha_1.h"
#include "utils.h"

#include <QByteArray>
#include <QCryptographicHash>
#include <QDebug>

namespace qossl {


QByteArray hmacSha1(const QByteArray &key, const QByteArray & message)
{
    const int blocksize = Sha1::BlockSizeBytes;
    QByteArray modifiedKey = key;
    if (key.length() > blocksize) {
        modifiedKey = Sha1::hash(key); // keys longer than blocksize are shortened
    }
    if (modifiedKey.length() < blocksize) {
        // keys shorter than blocksize are zero-padded
        modifiedKey = modifiedKey.append(QByteArray( (blocksize - modifiedKey.length()),'\0'));
    }

    const QByteArray o_key_pad = xorByteArray(modifiedKey,0x5c);
    const QByteArray i_key_pad = xorByteArray(modifiedKey,0x36);

    Sha1 hasher;
    hasher.addData(i_key_pad);
    hasher.addData(message);
    const QByteArray h1 = hasher.finalize();

    hasher.reset();
    hasher.addData(o_key_pad);
    hasher.addData(h1);
    return hasher.finalize();
}

QByteArray hmacSha256(const QByteArray &key, const QByteArray & message)
{
    const QCryptographicHash::Algorithm alg = QCryptographicHash::Sha256;
    const int blocksize = 64;
    QCryptographicHash hasher(alg);
    QByteArray modifiedKey = key;
    if (key.length() > blocksize) {
        hasher.addData(key);
        modifiedKey = hasher.result(); // keys longer than blocksize are shortened
        hasher.reset();
    }
    if (modifiedKey.length() < blocksize) {
        // keys shorter than blocksize are zero-padded
        modifiedKey = modifiedKey.append(QByteArray( (blocksize - modifiedKey.length()),'\0'));
    }

    const QByteArray o_key_pad = xorByteArray(modifiedKey,0x5c);
    const QByteArray i_key_pad = xorByteArray(modifiedKey,0x36);

    hasher.addData(i_key_pad);
    hasher.addData(message);
    const QByteArray h1 = hasher.result();

    hasher.reset();
    hasher.addData(o_key_pad);
    hasher.addData(h1);
    return hasher.result();
}

}
