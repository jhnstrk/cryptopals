#pragma once

class QByteArray;

namespace qossl {

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
}
