#include <jni.h>
#include <string>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <vector>
#include <cstring>

extern "C"
JNIEXPORT jstring JNICALL Java_com_example_tt_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}


extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_tt_MainActivity_encrypt(JNIEnv *env, jobject thiz, jbyteArray plaintext,
                                         jbyteArray key, jbyteArray iv) {
    // Convert Java byte arrays to C++ byte arrays
    jbyte* plaintextBytes = env->GetByteArrayElements(plaintext, nullptr);
    jbyte* keyBytes = env->GetByteArrayElements(key, nullptr);
    jbyte* ivBytes = env->GetByteArrayElements(iv, nullptr);

    jsize plaintextSize = env->GetArrayLength(plaintext);

    // Set up OpenSSL encryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    // Initialize encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<unsigned char*>(keyBytes), reinterpret_cast<unsigned char*>(ivBytes))) handleErrors();

    // Provide the message to be encrypted
    std::vector<unsigned char> ciphertext(plaintextSize + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len;
    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<unsigned char*>(plaintextBytes), plaintextSize)) handleErrors();
    int ciphertext_len = len;

    // Finalize encryption
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) handleErrors();
    ciphertext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    env->ReleaseByteArrayElements(plaintext, plaintextBytes, 0);
    env->ReleaseByteArrayElements(key, keyBytes, 0);
    env->ReleaseByteArrayElements(iv, ivBytes, 0);

    // Convert result to Java byte array
    jbyteArray result = env->NewByteArray(ciphertext_len);
    env->SetByteArrayRegion(result, 0, ciphertext_len, reinterpret_cast<jbyte*>(ciphertext.data()));

    return result;
}


extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_tt_MainActivity_decrypt(JNIEnv *env, jobject thiz, jbyteArray ciphertext,
                                         jbyteArray key, jbyteArray iv) {
    // Convert Java byte arrays to C++ byte arrays
    jbyte* ciphertextBytes = env->GetByteArrayElements(ciphertext, nullptr);
    jbyte* keyBytes = env->GetByteArrayElements(key, nullptr);
    jbyte* ivBytes = env->GetByteArrayElements(iv, nullptr);

    jsize ciphertextSize = env->GetArrayLength(ciphertext);

    // Set up OpenSSL decryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    // Initialize decryption operation
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<unsigned char*>(keyBytes), reinterpret_cast<unsigned char*>(ivBytes))) handleErrors();

    // Provide the message to be decrypted
    std::vector<unsigned char> plaintext(ciphertextSize);
    int len;
    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, reinterpret_cast<unsigned char*>(ciphertextBytes), ciphertextSize)) handleErrors();
    int plaintext_len = len;

    // Finalize decryption
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) handleErrors();
    plaintext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    env->ReleaseByteArrayElements(ciphertext, ciphertextBytes, 0);
    env->ReleaseByteArrayElements(key, keyBytes, 0);
    env->ReleaseByteArrayElements(iv, ivBytes, 0);

    // Convert result to Java byte array
    jbyteArray result = env->NewByteArray(plaintext_len);
    env->SetByteArrayRegion(result, 0, plaintext_len, reinterpret_cast<jbyte*>(plaintext.data()));

    return result;
}