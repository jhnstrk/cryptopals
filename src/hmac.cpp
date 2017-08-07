#include "hmac.h"

#include "sha_1.h"
#include "utils.h"

#include <QByteArray>
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

}
