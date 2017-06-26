#include "utils.h"

#include <openssl/bio.h>
#include <openssl/aes.h>

#include <QByteArray>
#include <QVector>

#include <QDebug>

#include <limits>

namespace qossl {

QByteArray xorByteArray(const QByteArray & src, const QByteArray & key)
{
    if (key.size() == 0) {
        return src;
    }

    QByteArray result;
    result.resize(src.size());

    for (int i=0; i<src.size(); ++i) {
        result[i] = src.at(i) ^ key.at(i % key.size());
    }
    return result;
}


// Method:
// Make a histogram of character frequencies (counts).
// Weight regular characters (A-Z, a-z, ' ') highest (1).
// Weight digits lower.
// Everying else gets zero weight.
// Normalize by length of the string.
double scoreEnglishText(const QByteArray &src)
{
    if (src.size() == 0) {
        return 0;
    }

    QVector<size_t> counts;
    counts.resize(256);
    for (int i=0; i<src.size(); ++i) {
        // Note: Without cast to unsigned char compiled code broke!
        ++counts[static_cast<unsigned char>(src.at(i))];
    }

    double result = 0;
    for (int i='A'; i<='Z'; ++i) {
        result += counts.at(i);
    }

    for (int i='a'; i<='z'; ++i) {
        result += counts.at(i);
    }

    for (int i='0'; i<='9'; ++i) {
        result += counts.at(i) * 0.2;  // Lower weight.
    }

    result += counts.at(' ');
    result += counts.at('\t') * 0.2;

    // Normalize w.r.t number of input chars.
    return result / static_cast<double>(src.size());
}

unsigned int countBitsSet( unsigned char c1 )
{
    // More efficient methods exist.
    // https://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetKernighan

    unsigned int v = c1;
    unsigned int c = 0;
    for (; v; v >>= 1)
    {
      c += v & 1;
    }
    return c;
}

unsigned int hammingDistance(const QByteArray &s1, const QByteArray &s2)
{
    // This could be more efficient by working in blocks or 4 or 8 bytes.
    if (s1.size() != s2.size()) {
        qCritical() << "Size mismatch";
        return std::numeric_limits<size_t>::max();
    }

    unsigned int result = 0;
    const int len = s1.size();
    for (int i=0; i<len; ++i) {
        const unsigned char c1= static_cast<unsigned char>(s1.at(i));
        const unsigned char c2= static_cast<unsigned char>(s2.at(i));

        const unsigned char mismatch = c1 ^ c2;
        result += countBitsSet(mismatch);
    }
    return result;
}

QByteArray subsample(const QByteArray &src, int start, int stride)
{
    QByteArray ret;
    if (start >= src.size()) {
        return ret;
    }

    const int len = (src.size() - start) / stride;

    ret.resize(len);
    for (int i=0; i<len; ++i) {
        ret[i] = src.at(start + (i*stride));
    }
    return ret;
}


QByteArray aesEcbDecrypt(const QByteArray &cipherText, const QByteArray &key)
{
    const int AesBlockSize = 16;

    AES_KEY dec_key;
    ::memset( &dec_key, 0, sizeof(dec_key));
    int status = AES_set_decrypt_key(reinterpret_cast<const unsigned char *>(key.constData()),
            key.size() * 8, &dec_key);
    if (status != 0){
        qWarning() << "Status"<< status;
        return QByteArray();
    }

    QByteArray out;
    int nblock = (cipherText.size()) / AesBlockSize;
    out.resize(nblock * AesBlockSize);

    if (cipherText.size() > nblock*AesBlockSize) {
        qWarning() << "Cipher text is not a multiple of the cipher block size.";
        --nblock;
    }

    const unsigned char * pIn = reinterpret_cast<const unsigned char*>(cipherText.constData());
    unsigned char *pOut = reinterpret_cast<unsigned char*>(out.data());

    for (int i=0; i<nblock; ++i) {
        AES_ecb_encrypt(
            pIn + i*AesBlockSize,
            pOut + i*AesBlockSize,
            &dec_key,
            AES_DECRYPT);
    }
    return out;
}

QByteArray pkcs7Pad(const QByteArray &data, const int blocksize)
{
    const int lastblock = (data.size() / blocksize) * blocksize;

    if (lastblock == data.size()) {
        // data is a multiple of the padding size
        return data;
    }

    const int n =  blocksize + lastblock - data.size();
    if (n > 255) {
        qWarning() << "PKCS7 overflow";
    }

    QByteArray ret;
    ret.reserve(lastblock + blocksize);
    ret += data;
    for (int i=0; i<n; ++i) {
        ret.append(static_cast<char>(n));
    }
    return ret;
}

}
