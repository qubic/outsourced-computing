#include <thread>
#include <chrono>
#include "stdio.h"
#include "connection.h"
#include "structs.h"
#include "keyUtils.h"
#include "K12AndKeyUtil.h"
#include "RandomX/src/randomx.h"
#include <stdexcept>
#include <map>
#include <mutex>
#include <queue>
#include <atomic>

#define DISPATCHER "XPXYKFLGSWRHRGAUKWFWVXCDVEYAPCPCNUTMUDWFGDYQCWZNJMWFZEEGCFFO"
uint8_t dispatcherPubkey[32] = {0};
#define PORT 21841
#define SLEEP(x) std::this_thread::sleep_for(std::chrono::milliseconds (x));
bool shouldExit = false;
uint64_t prevTask = 0;
struct task
{
    uint8_t sourcePublicKey[32]; // the source public key is the DISPATCHER public key
    uint8_t zero[32];  // empty/zero 0
    uint8_t gammingNonce[32];

    uint64_t taskIndex; // ever increasing number (unix timestamp in ms)

    uint8_t m_blob[408]; // Job data from pool
    uint64_t m_size;  // length of the blob
    uint64_t m_target; // Pool difficulty
    uint64_t m_height; // Block height
    uint8_t m_seed[32]; // Seed hash for XMR

    uint8_t signature[64];
};

struct solution
{
    uint8_t sourcePublicKey[32];
    uint8_t zero[32]; // empty/zero 0
    uint8_t gammingNonce[32];

    uint64_t _taskIndex;
    uint32_t nonce;         // xmrig::JobResult.nonce
    uint8_t result[32];   // xmrig::JobResult.result
    uint8_t pad[4];
    uint8_t signature[64];
} ;

// simple poc design and queue, need better design to have higher precision
std::mutex taskLock;
task currentTask;

std::mutex solLock;
std::queue<solution> qSol;
std::map<std::pair<uint64_t, uint32_t>, bool> mTaskNonce; // map task-nonce to avoid duplicated shares
std::atomic<uint64_t> gStale;
std::atomic<uint64_t> gInValid;
std::atomic<uint64_t> gValid;
std::atomic<int> nPeer;
#define XMR_NONCE_POS 39
#define XMR_VERIFY_THREAD 4

void verifyThread()
{
    task local_task;
    memset(&local_task, 0, sizeof(task));
    randomx_flags flags = randomx_get_flags();
    randomx_cache *cache = randomx_alloc_cache(flags);
    randomx_init_cache(cache, local_task.m_seed, 32);
    randomx_vm *vm = randomx_create_vm(flags, cache, NULL);
    while (currentTask.taskIndex == 0) SLEEP(100); // wait for the first job

    while (!shouldExit)
    {
        if (local_task.taskIndex != currentTask.taskIndex)
        {
            if (memcmp(local_task.m_seed, currentTask.m_seed, 32) != 0)
            {
                randomx_init_cache(cache, currentTask.m_seed, 32);
                randomx_vm_set_cache(vm, cache);
            }
            local_task = currentTask;
        }
        solution candidate;
        bool haveSol = false;
        {
            std::lock_guard<std::mutex> sl(solLock);
            if (!qSol.empty())
            {
                candidate = qSol.front();
                qSol.pop();
                haveSol = true;
            }

            // clean the key that has lower task index
            if (!mTaskNonce.empty())
            {
                std::vector<std::pair<uint64_t,uint32_t>> to_be_delete;
                for (auto const& item : mTaskNonce)
                {
                    if (item.first.first < currentTask.taskIndex)
                    {
                        to_be_delete.push_back(item.first);
                    }
                }
                for (auto const& item : to_be_delete)
                {
                    mTaskNonce.erase(item);
                }
            }
        }
        if (haveSol)
        {
            if (candidate._taskIndex < local_task.taskIndex)
            {
                gStale++;
                uint32_t nonce = candidate.nonce;
                printf("Stale Share from comp %d\n", nonce % 676);
                continue;
            }
            else if (candidate._taskIndex > local_task.taskIndex)
            {
                printf("Do not expected: Missing task - check your peers\n");
                continue;
            }
            uint8_t out[32];
            std::vector<uint8_t> blob;
            blob.resize(local_task.m_size, 0);
            memcpy(blob.data(), local_task.m_blob, local_task.m_size);
            uint32_t nonce = candidate.nonce;
            memcpy(blob.data() + XMR_NONCE_POS, &nonce, 4);
            randomx_calculate_hash(vm, blob.data(), local_task.m_size, out);
            uint64_t v = ((uint64_t*)out)[3];
            char hex[64];
            byteToHex(out, hex, 32);
            if (v < local_task.m_target)
            {
                gValid++;

                printf("Valid Share from comp %d: %s\n", nonce % 676, hex);
            }
            else
            {
                gInValid++;
                printf("Invalid Share from comp %d: %s\n", nonce % 676, hex);
            }
        }
        else
        {
            SLEEP(100);
        }
    }

    randomx_destroy_vm(vm);
    randomx_release_cache(cache);
}

void listenerThread(char* nodeIp)
{
    QCPtr qc;
    bool needReconnect = true;
    std::string log_header = "[" + std::string(nodeIp) + "]: ";
    while (!shouldExit)
    {
        try {
            if (needReconnect) {
                qc = make_qc(nodeIp, PORT);
                qc->exchangePeer();// do the handshake stuff
                needReconnect = false;
                nPeer++;
            }
            auto header = qc->receiveHeader();
            std::vector<uint8_t> buff;
            uint32_t sz = header.size();
            if (sz > 0xFFFFFF)
            {
                needReconnect = true;
                nPeer--;
                continue;
            }
            sz -= sizeof(RequestResponseHeader);
            buff.resize(sz);
            qc->receiveData(buff.data(), sz);
            if (header.type() == 1) // broadcast msg
            {
                if (buff.size() == sizeof(solution))
                {
                    solution* share = (solution*)buff.data();
                    char iden[64] = {0};
                    getIdentityFromPublicKey(share->sourcePublicKey, iden, false);
                    uint8_t sharedKeyAndGammingNonce[64];
                    memset(sharedKeyAndGammingNonce, 0, 32);
                    memcpy(&sharedKeyAndGammingNonce[32], share->gammingNonce, 32);
                    uint8_t gammingKey[32];
                    KangarooTwelve(sharedKeyAndGammingNonce, 64, gammingKey, 32);

                    if (gammingKey[0] != 2)
                    {
                        printf("Wrong type from comps (%s) No.%d. want %d | have %d\n", iden, share->nonce % 676, 2, gammingKey[0]);
                        continue;
                    }
                    {
                        std::lock_guard<std::mutex> slock(solLock);
                        auto p = std::make_pair(share->_taskIndex, share->nonce);
                        if (mTaskNonce.find(p) == mTaskNonce.end())
                        {
                            mTaskNonce[p] = true;
                            qSol.push(*share);
                        }
                    }
                }
                else if (buff.size() == 632)
                {
                    task* tk = (task*)buff.data();
                    if (memcmp(dispatcherPubkey, tk->sourcePublicKey, 32) != 0)
                    {
                        printf("Job not from dispatcher\n");
                        continue;
                    }
                    uint8_t sharedKeyAndGammingNonce[64];
                    memset(sharedKeyAndGammingNonce, 0, 32);
                    memcpy(&sharedKeyAndGammingNonce[32], tk->gammingNonce, 32);
                    uint8_t gammingKey[32];
                    KangarooTwelve(sharedKeyAndGammingNonce, 64, gammingKey, 32);
                    if (gammingKey[0] != 1)
                    {
                        printf("Wrong type from dispatcher\n");
                        continue;
                    }
                    uint8_t digest[32];
                    KangarooTwelve(buff.data(), buff.size() - 64, digest, 32);
                    if (!verify(dispatcherPubkey, digest, buff.data() + buff.size() - 64))
                    {
                        printf("Wrong sig from dispatcher\n");
                        continue;
                    }
                    {
                        std::lock_guard<std::mutex> glock(taskLock);
                        if (currentTask.taskIndex <  tk->taskIndex)
                        {
                            currentTask = *tk;
                        }
                        else
                        {
                            continue;
                        }
                    }
                    uint64_t delta = 0;
                    int64_t delta_local = 0;
                    {
                        auto now = std::chrono::system_clock::now();
                        // Convert the time point to milliseconds since the epoch (Unix timestamp)
                        auto duration = now.time_since_epoch();
                        auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
                        delta_local = (int64_t)(tk->taskIndex) - (int64_t)(milliseconds);
                    }
                    if (prevTask)
                    {
                        delta = (tk->taskIndex - prevTask);
                    }
                    prevTask = tk->taskIndex;
                    char dbg[256] = {0};
                    std::string debug_log = log_header;
                    sprintf(dbg, "Received task index %lu (d_prev: %lu ms) (d_local: %lu ms): ", tk->taskIndex, delta, delta_local);
                    debug_log += std::string(dbg); memset(dbg, 0, sizeof(dbg));
                    int blobSz = tk->m_size;
                    for (int i = 0; i < 4; i++)
                    {
                        char hex[8] = {0};
                        byteToHex(tk->m_blob + i, hex, 1);
                        debug_log += std::string(hex);
                    }
                    debug_log += "...";
                    for (int i = blobSz - 4; i < blobSz; i++)
                    {
                        char hex[8] = {0};
                        byteToHex(tk->m_blob + i, hex, 1);
                        debug_log += std::string(hex);
                    }

                    sprintf(dbg, " | diff %llu", 0xffffffffffffffffULL/tk->m_target);
                    debug_log += std::string(dbg); memset(dbg, 0, sizeof(dbg));
                    sprintf(dbg, " | height %lu\n", tk->m_height);
                    debug_log += std::string(dbg); memset(dbg, 0, sizeof(dbg));
                    printf("%s", debug_log.c_str());
                }
            }
            fflush(stdout);
        }
        catch (std::logic_error &ex) {
            printf("%s\n", ex.what());
            fflush(stdout);
            needReconnect = true;
            nPeer--;
            SLEEP(1000);
        }
    }
}

int run(int argc, char *argv[]) {
    if (argc == 1) {
        printf("./oc_verifier [nodeip0] [nodeip1] ... [nodeipN]\n");
        return 0;
    }
    getPublicKeyFromIdentity(DISPATCHER, dispatcherPubkey);
    std::vector<std::thread> thr;
    for (int i = 0; i < argc - 1; i++)
    {
        thr.push_back(std::thread(listenerThread, argv[1+i]));
    }

    std::thread verify_thr[XMR_VERIFY_THREAD];
    for (int i = 0; i < XMR_VERIFY_THREAD; i++)
    {
        verify_thr[i] = std::thread(verifyThread);
    }

    SLEEP(3000);
    while (!shouldExit)
    {
        printf("Active peer: %d | Valid: %lu | Invalid: %lu | Stale: %lu\n", nPeer.load(), gValid.load(), gInValid.load(), gStale.load());
        SLEEP(10000);
    }

    return 0;
}

int main(int argc, char *argv[]) {
    gStale = 0;
    gInValid = 0;
    gValid = 0;
    nPeer = 0;
    try {
        return run(argc, argv);
    }
    catch (std::exception &ex) {
        printf("%s\n", ex.what());
        return -1;
    }
}
