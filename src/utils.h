#pragma once

class QByteArray;

namespace qossl {

    QByteArray xorByteArray(const QByteArray & src, const QByteArray & key);

    // A simple score for plain ASCII English text.
    // higher is better, range is 0 to 1.
    double scoreEnglishText(const QByteArray & src);
}
