#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/evp.h>


void encodeJWT(const char *header, const char *payload, const char *secret) {
    
    char data[4096];
    snprintf(data, sizeof(data), "%s.%s", header, payload);

    
    unsigned char* digest = NULL;
    unsigned int digest_len;

    
    HMAC(EVP_sha256(), secret, strlen(secret), (unsigned char*)data, strlen(data), digest, &digest_len);

    
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new(BIO_s_mem());
    BIO_push(b64, mem);
    BIO_write(b64, digest, digest_len);
    BIO_flush(b64);

    char signature[4096];
    BIO_read(mem, signature, sizeof(signature));

    
    int signature_length = strlen(signature);
    if (signature[signature_length - 1] == '\n') {
        signature[signature_length - 1] = '\0';
    }

    
    char jwt[4096];
    snprintf(jwt, sizeof(jwt), "%s.%s.%s", header, payload, signature);

    printf("Encoded JWT: %s\n", jwt);
}

int main() {
    
    const char *header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    const char *payload = "{\"sub\":\"1234567890\",\"name\":\"John Doe\"}";
    const char *secret = "your_secret_key_here"; 

    encodeJWT(header, payload, secret);

    return 0;
}
