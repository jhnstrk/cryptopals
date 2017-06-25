#pragma once

#include <QCryptographicHash>
#include <QDebug>
#include <QScopedPointer>


#include <openssl/evp.h>

namespace qossl {

template < typename T, void (*TFunc)(T *) >
struct Deleter
{
    typedef QScopedPointer< T, Deleter< T, TFunc > > ScopedPointer;
    static inline void cleanup(T *p) { if (p) TFunc(p); }
};

// 'free' Functions that return int.
template < typename T, int (*TFunc)(T *) >
struct DeleterI
{
    typedef QScopedPointer< T, DeleterI< T, TFunc > > ScopedPointer;
    static inline void cleanup(T *p) { if (p) TFunc(p); }
};

const EVP_MD * digestFromMethod(QCryptographicHash::Algorithm method);

}
