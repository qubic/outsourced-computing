#pragma once
void getIdentityFromPublicKey(const uint8_t* pubkey, char* identity, bool isLowerCase);
void getPublicKeyFromIdentity(const char* identity, uint8_t* publicKey);
bool getSubseedFromSeed(const unsigned char* seed, unsigned char* subseed);
void getPrivateKeyFromSubSeed(const unsigned char* seed, unsigned char* privateKey);
void getPublicKeyFromPrivateKey(const unsigned char* privateKey, unsigned char* publicKey);