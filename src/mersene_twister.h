#pragma once

namespace qossl {


class MerseneTwister19937
{
public:
    // The default seed is the one used by C's rand.
    MerseneTwister19937(const unsigned int seed = 5489);
    ~MerseneTwister19937();

    void seed(const unsigned int value);
    // Extract a tempered value based on MT[index]
    // calling twist() every n numbers
    unsigned int extract_number();

private:
    // Generate the next n values from the series x_i
    void twist();
private:
    unsigned int index;
    unsigned int *MT; // [n]
};

}
