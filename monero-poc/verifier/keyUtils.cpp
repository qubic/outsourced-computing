#include <cstdint>
#include <vector>
#include "keyUtils.h"
#include "K12AndKeyUtil.h"
void getIdentityFromPublicKey(const uint8_t* pubkey, char* dstIdentity, bool isLowerCase)
{
    uint8_t publicKey[32] ;
    memcpy(publicKey, pubkey, 32);
    uint16_t identity[61] = {0};
    for (int i = 0; i < 4; i++)
    {
        unsigned long long publicKeyFragment = *((unsigned long long*)&publicKey[i << 3]);
        for (int j = 0; j < 14; j++)
        {
            identity[i * 14 + j] = publicKeyFragment % 26 + (isLowerCase ? L'a' : L'A');
            publicKeyFragment /= 26;
        }
    }
    unsigned int identityBytesChecksum;
    KangarooTwelve(publicKey, 32, (uint8_t*)&identityBytesChecksum, 3);
    identityBytesChecksum &= 0x3FFFF;
    for (int i = 0; i < 4; i++)
    {
        identity[56 + i] = identityBytesChecksum % 26 + (isLowerCase ? L'a' : L'A');
        identityBytesChecksum /= 26;
    }
    identity[60] = 0;
    for (int i = 0; i < 60; i++) dstIdentity[i] = char(identity[i]);
}

void getPublicKeyFromIdentity(const char* identity, uint8_t* publicKey)
{
    unsigned char publicKeyBuffer[32];
    for (int i = 0; i < 4; i++)
    {
        *((unsigned long long*)&publicKeyBuffer[i << 3]) = 0;
        for (int j = 14; j-- > 0; )
        {
            if (identity[i * 14 + j] < 'A' || identity[i * 14 + j] > 'Z')
            {
                return;
            }

            *((unsigned long long*)&publicKeyBuffer[i << 3]) = *((unsigned long long*)&publicKeyBuffer[i << 3]) * 26 + (identity[i * 14 + j] - 'A');
        }
    }
    memcpy(publicKey, publicKeyBuffer, 32);
}