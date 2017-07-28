#include "utils.h"

#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/rand.h>

#include <QByteArray>
#include <QUrlQuery>
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

QByteArray aesEcbEncrypt(const QByteArray &paddedPlainText, const QByteArray &key)
{
    AES_KEY enc_key;
    ::memset( &enc_key, 0, sizeof(enc_key));
    int status = AES_set_encrypt_key(reinterpret_cast<const unsigned char *>(key.constData()),
            key.size() * 8, &enc_key);
    if (status != 0){
        qWarning() << "Status"<< status;
        return QByteArray();
    }

    QByteArray out;
    int nblock = (paddedPlainText.size()) / AesBlockSize;
    out.resize(nblock * AesBlockSize);

    if (paddedPlainText.size() > nblock*AesBlockSize) {
        qWarning() << "Plain text is not a multiple of the cipher block size.";
        --nblock;
    }

    const unsigned char * pIn = reinterpret_cast<const unsigned char*>(paddedPlainText.constData());
    unsigned char *pOut = reinterpret_cast<unsigned char*>(out.data());

    for (int i=0; i<nblock; ++i) {
        AES_ecb_encrypt(
            pIn + i*AesBlockSize,
            pOut + i*AesBlockSize,
            &enc_key,
            AES_ENCRYPT);
    }
    return out;
}

QByteArray pkcs7Pad(const QByteArray &data, const int blocksize)
{
    if (data.isEmpty()) {
        return data; // Not sure what the spec is here; Add a block?
    }
    const int lastblock = (data.size() / blocksize) * blocksize;

    int n =  blocksize + lastblock - data.size();
    if (n > 255) {
        qWarning() << "PKCS7 overflow";
    }

    if (n == 0) {
        // data is a multiple of the padding size, we must add a complete block.
        n = blocksize;
    }
    QByteArray ret;
    ret.reserve(lastblock + blocksize);
    ret += data;
    for (int i=0; i<n; ++i) {
        ret.append(static_cast<char>(n));
    }
    return ret;
}

QByteArray pkcs7Unpad(const QByteArray &data, const int blocksize)
{
    if (data.isEmpty()) {
        return data;
    }

    const int lastVal = data.at(data.size() -1);

    if (lastVal > data.size()) {
        qCritical() << "Bad padding (Implied padding > data size)";
        return data;
    }

    if (blocksize != -1) {
        if (lastVal > blocksize) {
            qWarning() << "Bad padding (Implied padding > block size)";
        }
    }

    for (int i=data.size() -lastVal; i<data.size(); ++i) {
        if (data.at(i) != lastVal) {
            qWarning() << "Bad padding (Inconstistent last bytes)";
            return data;
        }
    }

    return data.mid(0, data.size() - lastVal);
}

QByteArray aesCbcDecrypt(const QByteArray &cipherText, const QByteArray &key, const QByteArray &iv)
{
    if (iv.size() != AesBlockSize) {
        qCritical() << "Bad I.V. size";
        return QByteArray();
    }

    if (key.size() != AesBlockSize) {
        qCritical() << "Bad key size";
        return QByteArray();
    }

    if (cipherText.size() % AesBlockSize != 0) {
        qWarning() << "Bad cipherText size, must be multiple of block size";
    }
    QByteArray plainText;
    plainText.reserve(cipherText.size());

    QByteArray lastBlock = iv;
    for (int i=0; i<cipherText.size()+1-AesBlockSize; i+=AesBlockSize) {
        QByteArray b1 = cipherText.mid(i,AesBlockSize);
        const QByteArray initBlock = b1;
        b1 = aesEcbDecrypt(b1, key);
        b1 = xorByteArray(b1,lastBlock);
        plainText.append(b1);
        lastBlock = initBlock;
    }
    return plainText;
}

QByteArray aesCbcEncrypt(const QByteArray &plainText, const QByteArray &key, const QByteArray &iv)
{
    if (iv.size() != AesBlockSize) {
        qCritical() << "Bad I.V. size";
        return QByteArray();
    }

    if (key.size() != AesBlockSize) {
        qCritical() << "Bad key size";
        return QByteArray();
    }

    if (plainText.size() % AesBlockSize != 0) {
        qWarning() << "Bad cipherText size, must be multiple of block size";
    }

    QByteArray cipherText;
    cipherText.reserve(plainText.size());

    QByteArray lastBlock = iv;
    for (int i=0; i<plainText.size()+1-AesBlockSize; i+=AesBlockSize) {
        QByteArray b1 = plainText.mid(i,AesBlockSize);
        b1 = xorByteArray(b1,lastBlock);
        b1 = aesEcbEncrypt(b1, key);
        cipherText.append(b1);
        lastBlock = b1;
    }
    return cipherText;
}

QByteArray randomBytes(int len)
{
    QByteArray ret(len, '\0');

    const int status = RAND_bytes(reinterpret_cast<unsigned char*>(ret.data()), len);
    if (status != 1) {
        qWarning() << "Random bytes not available";
    }

    return ret;
}

unsigned char randomUChar()
{
    unsigned char ret = 0;
    const int status = RAND_bytes(&ret, 1);
    if (status != 1) {
        qWarning() << "Random bytes not available";
    }

    return ret;
}

QByteArray randomAesKey(){
    return randomBytes(AesBlockSize);
}

//  Challenge 12

QHash<QByteArray, int> makeBlockHistogram(const QByteArray & data,  int blockSize)
{
    QHash<QByteArray, int> histo;

    // Break into 16 byte chunks and make a histogram.
    for (int i=0; i<data.size() - blockSize + 1; i+=blockSize) {
        const QByteArray chunk = data.mid(i,AesBlockSize);
        histo[chunk]++;
    }
    return histo;
}


double detectAesEcb(const QByteArray &cipherText)
{
    const QHash<QByteArray, int> histo = makeBlockHistogram(cipherText);

    // If many of the blocks appear more than once, that's suspicious.
    const int numBlocks = (cipherText.size() / AesBlockSize);
    const int dupCount = numBlocks - histo.size();
    return double (dupCount) / double (numBlocks);
}

Aes::Method estimateAesMethod(const QByteArray &cipherText) {
    return (detectAesEcb(cipherText) > 0.00001) ? Aes::ECB : Aes::CBC;
}

int detectBlockSize( EncryptionOracle & oracle )
{
    const int MaxBlock = 8096;  // Arbitrary upper limit.
    const int sz0 = oracle.encrypt(QByteArray()).size();
    int i1 = 0;
    int sz1 = 0;
    for(int i=0; i<MaxBlock; ++i) {
        sz1 = oracle.encrypt(QByteArray(i,'A')).size();
        if (sz1 != sz0) {
            i1 = i;
            break;
        }
    }

    if (i1 == 0) {
        qWarning() << "Unable to detect block size";
        return -1;
    }

    int sz2 = 0;
    int i2 = 0;
    for(int i=i1+1; i<MaxBlock; ++i) {
        sz2 = oracle.encrypt(QByteArray(i,'A')).size();
        if (sz2 != sz1) {
            i2 = i;
            break;
        }
    }

    return sz2 - sz1; // ????
}

QHash<QString, QString> keyValueParse(const QString & input){

    QUrlQuery query(input);
    QHash<QString, QString> ret;

    typedef QPair<QString, QString> StringPair;
    foreach (const StringPair & item, query.queryItems()) {

        ret[item.first] = item.second;

    }
    return ret;
}

QString profile_for(const QString & email)
{
    const int uid  = 10;
    const QString role = "user";
    QUrlQuery query;
    query.addQueryItem("email", email);
    query.addQueryItem("uid", QString::number(uid));
    query.addQueryItem("role", role);
    return query.toString();
}
}   // namespace qossl
