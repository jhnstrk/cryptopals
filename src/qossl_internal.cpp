#include "qossl_internal.h"

#include <openssl/obj_mac.h>

namespace Ossl {

const EVP_MD * digestFromMethod(QCryptographicHash::Algorithm method)
{
    switch(method){
    case QCryptographicHash::Sha256:
        return EVP_sha256();
    case QCryptographicHash::Sha384:
        return EVP_sha384();
    case QCryptographicHash::Sha512:
        return EVP_sha512();
    default:
        qWarning() << "Unknown algorithm";
        return Q_NULLPTR;
    }
}

}

