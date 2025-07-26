#include <stdint.h>
#include <cstring>
#include <vector>
#include "verifierLib.h"
#include "RandomX/src/randomx.h"
#include "xmr.h"

struct rxStruct
{
    randomx_cache *cache;
    randomx_vm *vm;
    uint8_t currentSeed[32];
    bool init;
};

void* createOCVerifier()
{
    rxStruct* ptr = new rxStruct();
    ptr->cache = nullptr;
    ptr->vm = nullptr;
    ptr->init = true;
    memset(ptr->currentSeed, 0, 32);

    randomx_flags flags = randomx_get_flags();
    ptr->cache = randomx_alloc_cache(flags);
    randomx_init_cache(ptr->cache, ptr->currentSeed, 32);
    ptr->vm = randomx_create_vm(flags, ptr->cache, NULL);
    return (void*)ptr;
}

void destroySolVerifier(void* ptr_)
{
    auto ptr = (rxStruct*)(ptr_);
    if (ptr->init)
    {
        randomx_destroy_vm(ptr->vm);
        randomx_release_cache(ptr->cache);
    }
    delete ptr;
}

bool verify(void *ptr_, task* _task, solution * _sol, uint8_t* out)
{
    auto ptr = (rxStruct*)(ptr_);
    if (memcmp(ptr->currentSeed, _task->m_seed, 32) != 0)
    {
        randomx_init_cache(ptr->cache, _task->m_seed, 32);
        randomx_vm_set_cache(ptr->vm, ptr->cache);
        memcpy(ptr->currentSeed, _task->m_seed, 32);
    }

    std::vector<uint8_t> block_template;
    block_template.resize(_task->m_size, 0);
    memcpy(block_template.data(), _task->m_template, _task->m_size);

    uint32_t extraNonce = _sol->_nonceu64 >> 32;
    uint32_t nonceu32 = _sol->_nonceu64 & 0xFFFFFFFFU;
    memcpy(block_template.data() + _task->m_extraNonceOffset, &extraNonce, 4);
    uint8_t hashing_blob[256] = {0};
    size_t hashing_blob_size = 0;

    get_hashing_blob(block_template.data(), _task->m_size, hashing_blob, &hashing_blob_size);
    memcpy(hashing_blob + 39, &nonceu32, 4);

    // do the hash
    randomx_calculate_hash(ptr->vm, hashing_blob, hashing_blob_size, out);

    uint64_t v = ((uint64_t*)out)[3];
    if (v < _task->m_target)
    {
        return true;
    }
    else
    {
        return false;
    }
}