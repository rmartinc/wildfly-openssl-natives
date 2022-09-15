#include "wfssl.h"

extern ssl_dynamic_methods ssl_methods;
extern crypto_dynamic_methods crypto_methods;

WF_OPENSSL(void, setSSLVerify)(JNIEnv *e, jobject o, jlong ssl, jint level, jint depth);

WF_OPENSSL(void, setSSLVerify)(JNIEnv *e, jobject o, jlong ssl, jint level, jint depth)
{
#pragma comment(linker, "/EXPORT:"__FUNCTION__"="__FUNCDNAME__)
    int verify = SSL_VERIFY_NONE;
    SSL *ssl_ = J2P(ssl, SSL *);

    if (ssl_ == NULL) {
        throwIllegalStateException(e, "ssl is null");
        return;
    }

    UNREFERENCED(o);

    if (level == SSL_CVERIFY_REQUIRE)
        verify |= SSL_VERIFY_PEER_STRICT;
    if ((level == SSL_CVERIFY_OPTIONAL) ||
        (level == SSL_CVERIFY_OPTIONAL_NO_CA))
        verify |= SSL_VERIFY_PEER;

    ssl_methods.SSL_set_verify(ssl_, verify, NULL);
    ssl_methods.SSL_set_verify_depth(ssl_, depth);
}
