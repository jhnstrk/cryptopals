#include "mersene_twister.h"

#include <QDebug>

namespace {
static const unsigned int w = 32;
static const unsigned int n = 624;
static const unsigned int m = 397;
static const unsigned int r = 31;
static const unsigned int a = 0x9908B0DFul;
static const unsigned int u = 11;
static const unsigned int d = 0xFFFFFFFFul;
static const unsigned int s = 7;
static const unsigned int b = 0x9D2C5680ul;
static const unsigned int t = 15;
static const unsigned int c = 0xEFC60000ul;
static const unsigned int l = 18;
static const unsigned int f = 1812433253ul;

static const unsigned int w_mask = 0xFFFFFFFFul ; // mask for 'lowest w bits of'
static const unsigned int lower_mask = (0x1ul << r) - 1ul;
static const unsigned int upper_mask = w_mask & (~lower_mask);
}

namespace qossl {

MerseneTwister19937::MerseneTwister19937(const unsigned int value) :
    index(n + 1),
    MT( new unsigned int [n])
{
    this->seed(value);
}

MerseneTwister19937::MerseneTwister19937(const QList<unsigned int> &state, unsigned int index) :
    index(index),
    MT( new unsigned int [n])
{
    for (unsigned int i=0; i<n; ++i) {
        MT[i] = state.at(i);
    }
}

MerseneTwister19937::~MerseneTwister19937()
{
    delete[] MT;
}

void MerseneTwister19937::seed(const unsigned int value)
{
    index = n;
    MT[0] = value;
    for (unsigned int i=1; i<n; ++i) {
        MT[i] = w_mask & (f * (MT[i-1] ^ (MT[i-1] >> (w-2))) + i);
    }
}

unsigned int MerseneTwister19937::extract_number()
{
    if (index >= n) {
        this->twist();
    }

    unsigned int y = MT[index];

    y = temper(y);

    index++;
    return w_mask & y;
}

int MerseneTwister19937::stateSize()
{
    return n;
}

unsigned int MerseneTwister19937::temper(unsigned int y)
{
    // Tempering.
    y ^= ((y >> u) & d);
    y ^= ((y << s) & b);
    y ^= ((y << t) & c);
    y ^= (y >> l);
    return y;
}

namespace {

    unsigned int un_left_shift_mask( const unsigned int z,
                                     const unsigned int s,
                                     const unsigned int mask)
    {
        // Objective: Reverse z = y ^ ( ( y << s ) & mask)
        unsigned int ret = z;

        // right most bits are not changed since the shift means they're xored with 0.
        for (unsigned int i = s; i < CHAR_BIT*sizeof(unsigned int); ++i) {
            // The bit at position i has been flipped if
            // the starting value bit at [i - s] was set
            // and the bit in mask[i] is set.
            ret ^= (mask & ( 1 << i )) & (ret << s );
        }

        return ret;
    }

    unsigned int un_right_shift_mask( const unsigned int z,
                                     const unsigned int s,
                                     const unsigned int mask)
    {
        // Objective: Reverse z = y ^ ( ( y >> s ) & mask)
        unsigned int ret = z;
        const unsigned int nbit = CHAR_BIT*sizeof(unsigned int);
        // left most bits are not changed since the shift means they're xored with 0.
        for (unsigned int i = s; i < nbit; ++i) {
            // The bit at position i has been flipped if
            // the starting value bit at [i + s] was set
            // and the bit in mask[i] is set.
            ret ^= (mask & ( 1 << (nbit - 1 - i) )) & (ret >> s );
        }

        return ret;
    }
}
unsigned int MerseneTwister19937::untemper(unsigned int y)
{
    // Un-Tempering.
    // y ^= (y >> l);
    y = un_right_shift_mask(y,l,w_mask);
    // y ^= ((y << t) & c);
    y = un_left_shift_mask(y, t, c);
    //y ^= ((y << s) & b);
    y = un_left_shift_mask(y, s, b);
    // y ^= ((y >> u) & d);
    y = un_right_shift_mask(y,u,d);

    return y;
}
void MerseneTwister19937::twist()
{
    for (unsigned int i = 0; i < n; ++i) {

        const unsigned int x = (MT[i] & upper_mask)
                + (MT[(i+1) % n] & lower_mask);

        unsigned int xA = x >> 1;

        if ( (x & 1ul) != 0) { // lowest bit of x is 1
            xA ^= a;
        }

        MT[i] = MT[(i + m) % n] ^ xA;
    }
    index = 0;
}

} // namespace

