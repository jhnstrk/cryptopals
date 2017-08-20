#include "utils.h"

#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/bn.h>

#include <QByteArray>
#include <QUrlQuery>
#include <QVector>

#include <QDebug>

#include <limits>

namespace qossl {

QByteArray xorByteArray(const QByteArray & src, const QByteArray & key)
{
    if ( (key.size() == 0) || (src.size() == 0) ) {
        return src;
    }

    QByteArray result;
    result.resize(src.size());

    for (int i=0; i<src.size(); ++i) {
        result[i] = src.at(i) ^ key.at(i % key.size());
    }
    return result;
}

QByteArray xorByteArray(const QByteArray & src, const unsigned char c)
{
    if (src.size() == 0) {
        return src;
    }

    QByteArray result;
    result.resize(src.size());

    for (int i=0; i<src.size(); ++i) {
        result[i] = ((unsigned char)src.at(i)) ^ c;
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
    result += counts.at('.') * 0.2;
    result += counts.at(',') * 0.2;

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
        return std::numeric_limits<unsigned int>::max();
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

int maxLen(const QList<QByteArray> & input) {
    int ret = 0;
    foreach (const QByteArray & item, input) {
        if (ret < item.size()) {
            ret = item.size();
        }
    }
    return ret;
}

int minLen(const QList<QByteArray> & input) {
    if (input.size() == 0) {
        return 0;
    }

    int ret = input.at(0).size();
    foreach (const QByteArray & item, input) {
        if (item.size() < ret) {
            ret = item.size();
        }
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
    const int lastblock = (data.size() / blocksize) * blocksize;

    int n =  blocksize + lastblock - data.size();
    if (blocksize > 255) {
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
        throw PaddingException("Bad padding");
    }

    const int lastVal = static_cast<unsigned char>(data.at(data.size() -1));

    if (lastVal == 0) {
        throw PaddingException("Bad padding");  // Not allowed by spec
    }

    if (lastVal > data.size()) {
        //qCritical() << "Bad padding (Implied padding > data size)";
        throw PaddingException("Bad padding");
    }

    if (blocksize != -1) {
        if (lastVal > blocksize) {
            //qWarning() << "Bad padding (Implied padding > block size)";
            throw PaddingException("Bad padding");
        }
    }

    for (int i=data.size() -lastVal; i<data.size(); ++i) {
        if (data.at(i) != lastVal) {
            //qWarning() << "Bad padding (Inconstistent last bytes)";
            throw PaddingException("Bad padding");
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

namespace {
// Littleendian copy.
    void copyUint64(QByteArray & b1, int at, quint64 v)
    {
        b1[at] = static_cast<char>(v & 0xFF);
        b1[at + 1] = static_cast<char>((v >> 8) & 0xFF);
        b1[at + 2] = static_cast<char>((v >> 16) & 0xFF);
        b1[at + 3] = static_cast<char>((v >> 24) & 0xFF);
        b1[at + 4] = static_cast<char>((v >> 32) & 0xFF);
        b1[at + 5] = static_cast<char>((v >> 40) & 0xFF);
        b1[at + 6] = static_cast<char>((v >> 48) & 0xFF);
        b1[at + 7] = static_cast<char>((v >> 56) & 0xFF);
    }
}

QByteArray aesCtrKeyStream(const QByteArray & key, quint64 nonce, quint64 first, quint64 len)
{
    if (key.size() != AesBlockSize) {
        qCritical() << "Bad key size";
        return QByteArray();
    }

    QByteArray countblock = QByteArray(AesBlockSize,'\0');
    copyUint64(countblock,0,nonce);
    quint64 counter = first / qossl::AesBlockSize;

    // lead-in: The offset within the first block.
    const int leadin = static_cast<int>(first - counter * qossl::AesBlockSize);

    QByteArray keyStream;
    keyStream.reserve(static_cast<int>(len) + leadin);

    for (int i = -leadin; i<(int)len; i+=AesBlockSize ) {
        copyUint64(countblock,8,counter);
        QByteArray ablock = aesEcbEncrypt(countblock,key);
        keyStream.append(ablock);
        ++counter;
    }

    return keyStream.mid(leadin,static_cast<int>(len));
}


QByteArray aesCtrEncrypt(const QByteArray & plainText, const QByteArray & key, quint64 nonce, quint64 count0)
{
    if (key.size() != AesBlockSize) {
        qCritical() << "Bad key size";
        return QByteArray();
    }

    QByteArray cipherText;
    cipherText.reserve(plainText.size());

    QByteArray countblock = QByteArray(AesBlockSize,'\0');
    copyUint64(countblock,0,nonce);
    quint64 counter = count0;
    for (int i = 0; i< plainText.size(); i+=AesBlockSize ) {
        copyUint64(countblock,8,counter);
        QByteArray ablock = aesEcbEncrypt(countblock,key);
        ablock = xorByteArray(plainText.mid(i,AesBlockSize),ablock);
        cipherText.append(ablock);
        ++counter;
    }
    return cipherText;
}

QByteArray aesCtrDecrypt(const QByteArray & cipherText, const QByteArray & key, quint64 nonce, quint64 count0)
{
    return aesCtrEncrypt(cipherText,key,nonce,count0);
}

bool aesCtrEdit(QByteArray &cipherText, const QByteArray &key, quint64 nonce, int offset, const QByteArray &newText)
{
    if (offset < 0) {
        qWarning() << "Bad offset in aesCtrEdit" << offset;
        return false;
    }
    
    const QByteArray keyBytes = aesCtrKeyStream(key,nonce,offset,newText.length());

    if (cipherText.size() < offset + newText.length()) {
        cipherText.resize(offset + newText.length());
    }

    unsigned char * p = reinterpret_cast<unsigned char*>(cipherText.data());
    for (int i=0; i<newText.length(); ++i) {
        p[i+offset] = (unsigned char)newText.at(i) ^ (unsigned char)keyBytes.at(i);
    }
    return true;
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

unsigned int randomUInt()
{
    union {
        unsigned int value;
        unsigned char bs[sizeof(unsigned int)];
    } ret;
    const int status = RAND_bytes(ret.bs, sizeof(unsigned int));
    if (status != 1) {
        qWarning() << "Random bytes not available";
    }
    return ret.value;
}

quint64 randomUInt64()
{
    union {
        quint64 value;
        unsigned char bs[sizeof(quint64)];
    } ret;
    const int status = RAND_bytes(ret.bs, sizeof(quint64));
    if (status != 1) {
        qWarning() << "Random bytes not available";
    }
    return ret.value;
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
    for(int i=i1+1; i<MaxBlock; ++i) {
        sz2 = oracle.encrypt(QByteArray(i,'A')).size();
        if (sz2 != sz1) {
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
    return query.toString(QUrl::FullyDecoded);
}

QList<QByteArray> splitBlocks(const QByteArray& input, int size)
{
    QList<QByteArray> ret;
    for (int i=0; i<input.size(); i+=size) {
        ret.append(input.mid(i,size));
    }
    return ret;
}

QByteArray repeated(const QByteArray &input, int count)
{
    QByteArray ret;
    ret.reserve(input.size() * count);
    for (int i=0; i<count; ++i) {
        ret.append(input);
    }
    return ret;
}

double findBestXorChar(const QByteArray &cipherText, QByteArray &bestPlain, int &bestCipherChar) {
    double maxScore = 0;
    int cipherChar = -1;
    for (int i=0; i<256; ++i) {
        QByteArray xorcodeBin(16,static_cast<char>(i));
        const QByteArray testPlain = xorByteArray(cipherText,xorcodeBin);
        const double score = scoreEnglishText(testPlain);
        if (score > maxScore) {
            maxScore = score;
            bestPlain = testPlain;
            cipherChar = i;
        }
    }
    bestCipherChar = cipherChar;
    return maxScore;
}

namespace {
    class BigNumDeleter {
    public:
        static void cleanup(BIGNUM *p)
        {
            if (p) {
                BN_free(p);
            }
        }
    };
}

QByteArray primeGen(int bits)
{
    if (bits <= 0) {
        qDebug() << "Number of bits requested is <=0" << bits;
        return QByteArray();
    }

    QScopedPointer< BIGNUM, BigNumDeleter > newPrime(BN_new());
    const int safe = 0;
    // If safe is true, it will be a safe prime (i.e. a prime p so that
    // (p-1)/2 is also prime)
    // If add is not NULL, the prime will fulfill the condition
    // p % add == rem (p % add == 1 if rem == NULL) in order to suit
    // a given generator.
    const BIGNUM *add = NULL;
    const BIGNUM *rem = NULL;

    // Callback to show some kind of progress.
    BN_GENCB *cb = NULL;
    int status = BN_generate_prime_ex(newPrime.data(), bits, safe,
                             add, rem, cb);
    if (status == 0) {
        qWarning() << "Prime generation failed";
        return QByteArray();
    }
    int numBytes = BN_num_bytes(newPrime.data());

    QByteArray ret(numBytes,Qt::Uninitialized);
    status = BN_bn2bin(newPrime.data(), reinterpret_cast<unsigned char *>(ret.data()));
    if (status == 0) {
        qWarning() << "Prime generation failed - couldn't copy.";
        return QByteArray();
    }

    return ret;
}

}   // namespace qossl
