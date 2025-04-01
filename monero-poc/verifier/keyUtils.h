#pragma once
void getIdentityFromPublicKey(const uint8_t* pubkey, char* identity, bool isLowerCase);
void getPublicKeyFromIdentity(const char* identity, uint8_t* publicKey);