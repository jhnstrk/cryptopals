#include "utils.h"

#include <QByteArray>
#include <QVector>

#include <QDebug>

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

}
