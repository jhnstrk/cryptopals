#pragma once

#include <QByteArray>
#include <QHash>
#include <QException>
#include <QString>

namespace qossl {

    class RuntimeException : public QException {
    public:
        RuntimeException(const QByteArray & what = QByteArray()): m_what(what) {}
        RuntimeException(const RuntimeException& other) : m_what(other.m_what) {}
        virtual ~RuntimeException() throw() {}

        virtual void raise() const Q_DECL_OVERRIDE { throw *this; }
        virtual QException *clone() const Q_DECL_OVERRIDE { return new RuntimeException(*this); }
        virtual const char* what() const Q_DECL_OVERRIDE throw() { return m_what.constData(); }

        const QByteArray & whatBytes() const throw() { return m_what; }
    private:
        QByteArray m_what;
    };
    class PaddingException : public RuntimeException {
    public:
        PaddingException(const QByteArray & what = QByteArray()): RuntimeException(what) {}
        PaddingException(const PaddingException& other) : RuntimeException(other) {}
        virtual ~PaddingException() throw() {}

        virtual void raise() const Q_DECL_OVERRIDE { throw *this; }
        virtual QException *clone() const Q_DECL_OVERRIDE { return new PaddingException(*this); }
    };

    enum { AesBlockSize = 16 };

    QByteArray xorByteArray(const QByteArray & src, const QByteArray & key);
    QByteArray xorByteArray(const QByteArray & src, const unsigned char c);

    // A simple score for plain ASCII English text.
    // higher is better, range is 0 to 1.
    double scoreEnglishText(const QByteArray & src);

    // Input must be same length
    unsigned int hammingDistance(const QByteArray & s1, const QByteArray & s2);

    //! Return the number of bits set in the given char.
    unsigned int countBitsSet(unsigned char c);

    double findBestXorChar(const QByteArray & cipherText, QByteArray & bestPlain, int & bestCipherChar);

    //! Sub-sample byte array.
    QByteArray subsample(const QByteArray & src, int start, int stride);

    //! Max, Min lengths of arrays in list.
    int maxLen(const QList<QByteArray> & input);
    int minLen(const QList<QByteArray> & input);

    //! AES-128 ECB decryption
    QByteArray aesEcbDecrypt(const QByteArray & cipherText, const QByteArray & key);

    //! AES-128 ECB encryption
    QByteArray aesEcbEncrypt(const QByteArray & paddedPlainText, const QByteArray & key);

    //! Pad data.
    QByteArray pkcs7Pad(const QByteArray & data, const int blocksize);
    QByteArray pkcs7Unpad(const QByteArray & data, const int blocksize = -1);

    //! AES CBC
    //! Inputs must be a multiple of the AES block size.
    QByteArray aesCbcDecrypt(const QByteArray & cipherText, const QByteArray & key, const QByteArray & iv);
    QByteArray aesCbcEncrypt(const QByteArray & plainText, const QByteArray & key, const QByteArray & iv);

    //! AES CTR
    QByteArray aesCtrDecrypt(const QByteArray & cipherText, const QByteArray & key, quint64 nonce, quint64 count0);
    QByteArray aesCtrEncrypt(const QByteArray & plainText, const QByteArray & key, quint64 nonce, quint64 count0);

    bool aesCtrEdit(QByteArray & cipherText, const QByteArray & key, quint64 nonce, int offset, const QByteArray & newText);
    
    // Find a prime with n-bits that optionally also satisfies
    // p%add = 1 -> i.e. p-1 is a multiple of add.
    QByteArray primeGen(int bits, const QByteArray & add = QByteArray());

    //! Generate len cryptographic random bytes.
    QByteArray randomBytes(int len);
    unsigned char   randomUChar();
    unsigned int    randomUInt();
    quint64         randomUInt64();

    QByteArray randomAesKey();

    namespace Aes
    {
        enum Method { None, ECB, CBC };
    }

    namespace Padding {
        enum Padding { None, Pkcs7 };
    }

    class EncryptionOracle {
    public:
        EncryptionOracle() {}
        virtual ~EncryptionOracle() {}
        virtual QByteArray encrypt(const QByteArray & input) = 0;
    };

    QHash<QByteArray, int> makeBlockHistogram(const QByteArray & data,  int blockSize = AesBlockSize);

    double detectAesEcb(const QByteArray & data);

    Aes::Method estimateAesMethod(const QByteArray & cipherText);

    int detectBlockSize( EncryptionOracle & oracle );

    QHash<QString, QString> keyValueParse(const QString & input);

    // Split into blocks
    QList<QByteArray> splitBlocks(const QByteArray & input,int size = AesBlockSize);

    QByteArray repeated(const QByteArray & input, int count);

    QString profile_for(const QString & email);
}
