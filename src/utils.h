#pragma once

#include <QByteArray>
#include <QHash>

namespace qossl {

    enum { AesBlockSize = 16 };

    QByteArray xorByteArray(const QByteArray & src, const QByteArray & key);

    // A simple score for plain ASCII English text.
    // higher is better, range is 0 to 1.
    double scoreEnglishText(const QByteArray & src);

    // Input must be same length
    unsigned int hammingDistance(const QByteArray & s1, const QByteArray & s2);

    //! Return the number of bits set in the given char.
    unsigned int countBitsSet(unsigned char c);

    //! Sub-sample byte array.
    QByteArray subsample(const QByteArray & src, int start, int stride);

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

    //! Generate len cryptographic random bytes.
    QByteArray randomBytes(int len);
    unsigned char   randomUChar();

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
}
