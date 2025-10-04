#include <thread>
#include <chrono>
#include "stdio.h"
#include "connection.h"
#include "structs.h"
#include "keyUtils.h"
#include "K12AndKeyUtil.h"
#include <stdexcept>
#include <map>
#include <mutex>
#include <queue>
#include <atomic>
#include <sstream>
#include <csignal>
#include <iostream>
#include <string>
#include <vector>

#include "verifierLib.h"

int getComputorIDFromSol(const solution *_sol)
{
    int computorID = 0;
    if (_sol->encryptionLevel == 0)
    {
        computorID = (_sol->combinedNonce >> 32ULL) % 676ULL;
    }
    else
    {
        computorID = _sol->computorRandom % 676ULL;
    }
    return computorID;
}


static char DISPATCHER_SEED[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static char COMPUTOR_SEED[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

static unsigned char DISPATCHER_SUBSEED[32];
static unsigned char DISPATCHER_PUBLICKEY[32];
static char DISPATCHER_ID[128];

static unsigned char COMPUTOR_SUBSEED[32];
static unsigned char COMPUTOR_PUBLICKEY[32];
static char COMPUTOR_ID[128];

void getKey(const char *seed, unsigned char *subSeed, unsigned char *pubKey, char *identity)
{
    unsigned char privateKey[32];
    getSubseedFromSeed((unsigned char *)seed, subSeed);
    getPrivateKeyFromSubSeed(subSeed, privateKey);
    getPublicKeyFromPrivateKey(privateKey, pubKey);
    getIdentityFromPublicKey(pubKey, identity, false);
}

void printHelp() {
    std::cout << "Usage: testnetDispatcher <nodeIP> <nodePort> <rateLimitPerMin> <sharePerTask> [legacyNonce] [dispatcherSeed] [computorSeeds]\n";
    std::cout << "  nodeIP          - IP of the node\n";
    std::cout << "  nodePort        - Port of the node\n";
    std::cout << "  rateLimitPerMin - Requests per minute\n";
    std::cout << "  sharePerTask    - Number of shares per task\n";
    std::cout << "  legacyNonce     - (optional) 0 or 1, default = 1\n";
    std::cout << "  dispatcherSeed  - (optional) dispatcher seed string\n";
    std::cout << "  computorSeeds   - (optional) computor seeds string\n";
}

std::atomic<bool> shouldExit(false);

#define BROADCAST_MESSAGE 1
#define MESSAGE_TYPE_CUSTOM_MINING_TASK 1
#define MESSAGE_TYPE_CUSTOM_MINING_SOLUTION 2

// Task packet
struct TaskPacket
{
    RequestResponseHeader header;
    task payload;
};

// Share packet
struct SharePacket
{
    RequestResponseHeader header;
    solution payload;
};

inline void fillRandom32(unsigned char *buf)
{
    // Thread-local fallback generator
    thread_local std::mt19937_64 gen(std::random_device{}());
    for (int i = 0; i < 4; i++)
    {
        auto val = gen();
        std::memcpy(buf + i * 8, &val, 8);
    }
}

inline uint32_t randomU32()
{
    thread_local std::mt19937 gen(std::random_device{}());
    std::uniform_int_distribution<uint32_t> dist(0, 0xFFFFFFFFu);
    return dist(gen);
}

TaskPacket createTask()
{
    // Craft a task
    task taskMessage;

    memcpy(taskMessage.sourcePublicKey, DISPATCHER_PUBLICKEY, sizeof(taskMessage.sourcePublicKey));

    // Zero destination is used for custom mining
    memset(taskMessage.zero, 0, sizeof(taskMessage.zero));

    // Payload of a dummy task
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    taskMessage.taskIndex = (uint64_t)milliseconds;
    // Fill dummy data
    taskMessage.m_height = 3511959;
    taskMessage.m_size = 825;
    taskMessage.m_extraNonceOffset = 174;

    // Gamming nonce
    unsigned char sharedKeyAndGammingNonce[64];
    // Default behavior when provided seed is just a signing address
    // first 32 bytes of sharedKeyAndGammingNonce is set as zeros
    memset(sharedKeyAndGammingNonce, 0, 32);

    // Last 32 bytes of sharedKeyAndGammingNonce is randomly created so that gammingKey[0] = 0 (MESSAGE_TYPE_CUSTOM_MINING_TASK)
    unsigned char gammingKey[32];
    do
    {
        fillRandom32(taskMessage.gammingNonce);
        memcpy(&sharedKeyAndGammingNonce[32], taskMessage.gammingNonce, 32);
        KangarooTwelve(sharedKeyAndGammingNonce, 64, gammingKey, 32);
    } while (gammingKey[0] != MESSAGE_TYPE_CUSTOM_MINING_TASK);

    // Sign the message
    uint8_t digest[32] = {0};
    uint8_t signature[64] = {0};
    KangarooTwelve(
        (unsigned char *)&taskMessage,
        sizeof(taskMessage) - SIGNATURE_SIZE,
        digest,
        32);
    sign(DISPATCHER_SUBSEED, DISPATCHER_PUBLICKEY, digest, signature);
    memcpy(taskMessage.signature, signature, 64);

    TaskPacket packet;
    packet.header.setSize(sizeof(packet));
    packet.header.zeroDejavu();
    packet.header.setType(BROADCAST_MESSAGE);
    packet.payload = taskMessage;

    return packet;
}

solution createShare(task &rTask, bool legacyNonce)
{
    solution share;
    share.taskIndex = rTask.taskIndex;
    memcpy(share.sourcePublicKey, COMPUTOR_PUBLICKEY, 32);

    // Zero destination is used for custom mining
    memset(share.zero, 0, sizeof(share.zero));

    // Fill dummy data
    if (legacyNonce)
    {
        share.encryptionLevel = 0;
        uint32_t extraNonce = randomU32();
        uint32_t nonce = randomU32();
        share.combinedNonce = ((uint64_t)extraNonce << 32) | (uint64_t)nonce;
    }
    else
    {
        share.encryptionLevel = 2;
        share.computorRandom = randomU32();
        uint32_t extraNonce = randomU32();
        uint32_t nonce = randomU32();
        share.combinedNonce = ((uint64_t)extraNonce << 32) | (uint64_t)nonce;
    }

    // Gamming nonce
    unsigned char sharedKeyAndGammingNonce[64];
    // Default behavior when provided seed is just a signing address
    // first 32 bytes of sharedKeyAndGammingNonce is set as zeros
    memset(sharedKeyAndGammingNonce, 0, 32);

    // Last 32 bytes of sharedKeyAndGammingNonce is randomly created so that gammingKey[0] = 0 (MESSAGE_TYPE_CUSTOM_MINING_TASK)
    unsigned char gammingKey[32];
    do
    {
        fillRandom32(share.gammingNonce);
        memcpy(&sharedKeyAndGammingNonce[32], share.gammingNonce, 32);
        KangarooTwelve(sharedKeyAndGammingNonce, 64, gammingKey, 32);
    } while (gammingKey[0] != MESSAGE_TYPE_CUSTOM_MINING_SOLUTION);

    // Sign the message
    uint8_t digest[32] = {0};
    uint8_t signature[64] = {0};
    KangarooTwelve(
        (unsigned char *)&share,
        sizeof(share) - SIGNATURE_SIZE,
        digest,
        32);
    sign(COMPUTOR_SUBSEED, COMPUTOR_PUBLICKEY, digest, signature);
    memcpy(share.signature, signature, 64);
    return share;
}

std::vector<SharePacket> createShares(task &rTask, int sharePerTask, bool legacyNonce)
{
    std::vector<SharePacket> packets;
    for (int i = 0; i < sharePerTask; i++)
    {
        solution share = createShare(rTask, legacyNonce);

        SharePacket packet;
        packet.header.setSize(sizeof(packet));
        packet.header.zeroDejavu();
        packet.header.setType(BROADCAST_MESSAGE);
        packet.payload = share;

        packets.push_back(packet);
    }
    return packets;
}

void sendTaskAndShare(QCPtr pConnection, int sharePerTask, bool legacyNonce)
{

    TaskPacket taskPacket = createTask();
    std::vector<SharePacket> shares = createShares(taskPacket.payload, sharePerTask, legacyNonce);

    // Send
    uint64_t dataSent = pConnection->sendData((uint8_t *)&taskPacket, sizeof(taskPacket));
    if (dataSent == sizeof(taskPacket))
    {
        std::cout << "Sent a task " << taskPacket.payload.taskIndex << std::endl;
    }

    for (int i = 0; i < shares.size(); i++)
    {
        dataSent = pConnection->sendData((uint8_t *)&shares[i], sizeof(SharePacket));
        if (dataSent == sizeof(SharePacket))
        {
            std::cout << "Sent xmr share for compId  " << getComputorIDFromSol(&(shares[i].payload))
                      << "( " << shares[i].payload.combinedNonce << ")" << std::endl;
        }
    }
}

void dispatchRun(const char *nodeIp, int nodePort, int rateLimitPerMin, int sharePerTask, bool legacyNonce)
{
    int64_t timeBetweenSend = 60000 / std::max(rateLimitPerMin, 1);
    auto startTime = std::chrono::system_clock::now();
    QCPtr qc;
    bool needReconnect = true;
    while (!shouldExit.load())
    {
        try
        {
            if (needReconnect)
            {
                needReconnect = false;
                qc = make_qc(nodeIp, nodePort);
                startTime = std::chrono::system_clock::now();
            }

            // Send task and sols
            sendTaskAndShare(qc, sharePerTask, legacyNonce);

            std::this_thread::sleep_for(std::chrono::milliseconds(timeBetweenSend));
            // Check timeout
            if (std::chrono::system_clock::now() - startTime > std::chrono::milliseconds(10000)) 
            {
                needReconnect = true;
            }
        }
        catch (std::logic_error &ex)
        {
            std::cout << ex.what() << std::endl;
            fflush(stdout);
            needReconnect = true;
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
        catch (...)
        {
            std::cout << "Unknown exception caught!\n";
            fflush(stdout);
            needReconnect = true;
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
    }
}

int run(int argc, char *argv[])
{
    if (argc < 5) 
    {
        printHelp();
        return 1;
    }

    std::string nodeIP        = argv[1];
    int nodePort              = std::stoi(argv[2]);
    int rateLimitPerMin       = std::stoi(argv[3]);
    int sharePerTask          = std::stoi(argv[4]);

    bool legacyNonce = true;
    if (argc >= 6) 
    {
        legacyNonce = std::stoi(argv[5]) > 0;
    }

    if (argc >= 7) 
    {
        std::strncpy(DISPATCHER_SEED, argv[6], sizeof(DISPATCHER_SEED) - 1);
        DISPATCHER_SEED[sizeof(DISPATCHER_SEED) - 1] = '\0'; // ensure null termination
    }

    if (argc >= 8) {
        std::strncpy(COMPUTOR_SEED, argv[7], sizeof(COMPUTOR_SEED) - 1);
        COMPUTOR_SEED[sizeof(COMPUTOR_SEED) - 1] = '\0';
    }


    // Dispatcher
    getKey(DISPATCHER_SEED, DISPATCHER_SUBSEED, DISPATCHER_PUBLICKEY, DISPATCHER_ID);

    // Owned computors
    getKey(COMPUTOR_SEED, COMPUTOR_SUBSEED, COMPUTOR_PUBLICKEY, COMPUTOR_ID);

    std::cout << "dispatcher: " << DISPATCHER_ID << "\n";
    std::cout << "submit shares via: " << COMPUTOR_ID << "\n";

    dispatchRun(nodeIP.c_str(), nodePort, rateLimitPerMin, sharePerTask, legacyNonce);

    return 0;
}

int main(int argc, char *argv[])
{

#ifndef _MSC_VER
    // Ignore SIGPIPE globally
    std::signal(SIGPIPE, SIG_IGN);
#endif
    try
    {
        return run(argc, argv);
    }
    catch (std::exception &ex)
    {
        printf("%s\n", ex.what());
        return -1;
    }
}
