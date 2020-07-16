#pragma once

#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>

int createCA(X509 **cert, FILE *fp);
int createUser(X509 **cert, FILE *fp, EC_POINT *Pu, const EC_GROUP *g, X509 *cacert, EC_KEY *cakey);