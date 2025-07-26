#pragma once
struct task
{
    unsigned char sourcePublicKey[32]; // the source public key is the DISPATCHER public key
    unsigned char zero[32];  // empty/zero 0
    unsigned char gammingNonce[32];

    unsigned long long taskIndex;
    unsigned char m_template[896];
    unsigned long long m_extraNonceOffset;
    unsigned long long m_size;
    unsigned long long m_target;
    unsigned long long m_height;
    unsigned char m_seed[32];

    unsigned char signature[64];
};

struct solution
{
    unsigned char sourcePublicKey[32];
    unsigned char zero[32]; // empty/zero 0
    unsigned char gammingNonce[32];

    unsigned long long _taskIndex;
    unsigned long long _nonceu64; // (extraNonce<<32) | nonce
    unsigned long long reserve0;
    unsigned long long reserve1;
    unsigned long long reserve2;

    unsigned char result[32];   // xmrig::JobResult.result
    unsigned char signature[64];
} ;
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Create qubic OC verifier instance
 * return a pointer of verifier instance if success
 * otherwise, return null pointer
 * */
void* createOCVerifier();

/*
 * Destroy qubic OC verifier instance
 * must be called before exitting program
 * */
void destroySolVerifier(void* ptr_);

/*
 * Calculating score from pubkey(32 bytes) and nonce(32 bytes)
 * */
bool verify(void *ptr_, task* _task, solution * _sol, unsigned char* out);
#ifdef __cplusplus
}
#endif