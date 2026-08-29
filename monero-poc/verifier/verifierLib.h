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

    unsigned long long taskIndex;
    unsigned long long combinedNonce; // (extraNonce<<32) | nonce
    unsigned long long encryptionLevel; // 0 = no encryption, 2 = EP173+ encryption
    unsigned long long computorRandom; // random number which fullfils the condition computorRandom % 676 == ComputorIndex
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
 * Verifying pair (task,sol) if it's valid
 * */
bool verify(void *ptr_, const task* _task, const solution * _sol, unsigned char* out);

/*
 * Get the computor ID from a solution
 **/
int getComputorIDFromSol(const solution* _sol);

/**
 * @brief Decrypt the solutions.
 *
 * Currently, this function is implemented as a no-op (solutions are not actually encrypted).
 *
 * @param[in] encryptedSol         Pointer to the encrypted solution data.
 * @param[in] encryptedSolSizeInBytes Size of the encrypted solution data in bytes.
 * @param[in] extraData            Pointer to additional data required for decryption.
 * @param[in] extraDataSizeInbytes Size of the extra data in bytes.
 * @param[out] out                 Pointer to the decrypted solution output.
 *
 * @return 0 if successful.
 */
int decryptSolution(const unsigned char * encryptedSol, const unsigned long long encryptedSolSizeInBytes,
    const unsigned char * extraData, const unsigned long long extraDataSizeInbytes,
    solution* out);

#ifdef __cplusplus
}
#endif