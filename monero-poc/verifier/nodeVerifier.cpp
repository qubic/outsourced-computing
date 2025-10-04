#include "nodeVerifier.h"

#include "verifierLib.h"
#include "connection.h"
#include "keyUtils.h"
#include "K12AndKeyUtil.h"

#include <thread>
#include <chrono>
#include <mutex>
#include <atomic>
#include <map>
#include <iostream>
#include <sstream>

// Message struture for request custom mining data
struct RequestedCustomMiningData
{
    enum
    {
        type = 60,
    };
    enum
    {
        taskType = 0,
        solutionType = 1,
    };
    // Task index information:
    // - For taskType: 'fromTaskIndex' is the lower bound and 'toTaskIndex' is the upper bound of the task range [fromTaskIndex, toTaskIndex].
    // - For solutionType: only 'fromTaskIndex' is used, since the solution response is tied to a single task.
    unsigned long long fromTaskIndex;
    unsigned long long toTaskIndex;

    // Type of the request: either task (taskType) or solution (solutionType).
    long long dataType;
};

// Message struture for respond custom mining data
struct RespondCustomMiningData
{
    enum
    {
        type = 61,
    };
    enum
    {
        taskType = 0,
        solutionType = 1,
    };
    // The 'payload' variable is defined externally and usually contains a byte array.
    // Ussualy: [CustomMiningRespondDataHeader ... NumberOfItems * ItemSize];
};

struct RequestedCustomMiningSolutionVerification
{
    enum
    {
        type = 62,
    };
    unsigned long long taskIndex;
    unsigned long long nonce;
    unsigned long long encryptionLevel;
    unsigned long long computorRandom;
    unsigned long long reserve2;
    unsigned long long isValid; // validity of the solution. 0: invalid, >0: valid
};
struct RespondCustomMiningSolutionVerification
{
    enum
    {
        type = 63,
    };
    enum
    {
        notExisted = 0,             // solution not existed in cache
        valid = 1,                  // solution are set as valid
        invalid = 2,                // solution are set as invalid
        customMiningStateEnded = 3, // not in custom mining state
    };
    unsigned long long taskIndex;
    unsigned long long nonce;
    unsigned long long encryptionLevel;
    unsigned long long computorRandom;
    unsigned long long reserve2;
    long long status; // Flag indicate the status of solution
};

struct CustomMiningRespondDataHeader
{
    unsigned long long itemCount;     // size of the data
    unsigned long long itemSize;      // size of the data
    unsigned long long fromTimeStamp; // start of the ts
    unsigned long long toTimeStamp;   // end of the ts
    unsigned long long respondType;   // message type
};

constexpr uint64_t taskPayloadOffset = 3 * 32;                                          // pubKey, zeros, gammingNonce and signature;
constexpr uint64_t taskPayloadSize = sizeof(task) - taskPayloadOffset - 64;             // minus pubKey, zeros, gammingNonce and signature;
constexpr uint64_t solutionPayloadOffset = 3 * 32;                                      // pubKey, zeros, gammingNonce and signature;
constexpr uint64_t solutionPayloadSize = sizeof(solution) - solutionPayloadOffset - 64; // minus pubKey, zeros, gammingNonce and signature;

// Timeout of a connection. Increase it if the connection is robust
constexpr uint64_t NODE_CONNECTION_TIMEOUT = 10000; // 11000 is set in connection implementation, so 10000 is chosen
// This will allow us to get late arrival task
constexpr int64_t TIME_WINDOWS_OFFSET_IN_MS = 10000;
// Params controls avoid we stay in submitted loops for too long
constexpr int64_t REPORTED_TIMEOUT_IN_MS = 10000;

class NodeVerifier
{
public:
    NodeVerifier(const char *nodeIp, int nodePort, const char *operatorSeed);
    ~NodeVerifier();

    // Lauch thread to get solutions from node and do verification
    int launch();

    // Stop verification thread
    int stop();

    // Add a solution into submitteed queue
    int addVerifiedSolutions(solution *pSolution, bool isValid);

    void printStats();

    RequestedCustomMiningSolutionVerification convertFromSolution(const solution &rSolution, bool isValid);

private:
    // Thread that continuously get task and solution from nodes
    void getSolutionsThread();
    bool fetchCustomMiningData(QCPtr pConnection, const char *logHeader);
    void getCustomMiningSolutions(QCPtr pConnection, const char *logHeader, const std::map<uint64_t, task> &nodeTask);
    void verifySolutionFromNode(const task &rTask, std::vector<solution> &rSolutions);

    // Thread continously submit verified solutions if there is any
    void submitVerifiedSolutionsThread();
    bool reportVerifiedSol(QCPtr pConnection);

    void getKey(const char *operatorSeed);
    std::vector<unsigned char> waitForPackage( QCPtr pConnection, int packageType, int64_t timeOut);

    std::atomic<bool> mIsRunning;
    std::unique_ptr<std::thread> mVerifierThread;
    uint64_t mLastTaskTimeStamp;
    std::map<uint64_t, task> mNodeTasks;                      // Task that fetching from node
    std::map<uint64_t, std::vector<solution>> mNodeSolutions; // Solutions that fetching from node

    uint8_t *mOcVerifier;

    uint8_t mOperatorPublicKey[32];
    uint8_t mOperatorSubSeed[32];
    uint8_t operatorPrivateKey[32];
    char mOperatorPublicIdentity[128];

    std::string mNodeIP;
    int mNodePort;

    // Solutions are verified and wait for reported to node
    std::vector<RequestedCustomMiningSolutionVerification> mReportedSolutionsVec;
    std::mutex mValidSolLock;
    std::atomic<uint64_t> mSubmittedSolutionsCount;
    std::atomic<uint64_t> mTotalSolutions;
    std::atomic<uint64_t> mValidSolutionsCount;
    std::atomic<uint64_t> mInvalidSolutionsCount;

#if TESTNET_ENABLE
    unsigned long long mDummyCounter;
    std::mutex mDummyLock;
#endif
};

NodeVerifier::NodeVerifier(const char *nodeIp, int nodePort, const char *operatorSeed)
{
    mIsRunning = false;
    mVerifierThread = nullptr;
    mLastTaskTimeStamp = 0;
    mNodeTasks.clear();     // Task that fetching from node
    mNodeSolutions.clear(); // Solutions that fetching from node
    mOcVerifier = nullptr;
    memset(mOperatorPublicKey, 0, sizeof(mOperatorPublicKey));
    memset(mOperatorSubSeed, 0, sizeof(mOperatorSubSeed));
    memset(operatorPrivateKey, 0, sizeof(operatorPrivateKey));
    memset(mOperatorPublicIdentity, 0, sizeof(mOperatorPublicIdentity));
    mNodeIP = nodeIp;
    mNodePort = nodePort;
    mSubmittedSolutionsCount = 0;
    mTotalSolutions = 0;
    mValidSolutionsCount = 0;
    mInvalidSolutionsCount = 0;

#if TESTNET_ENABLE
    mDummyCounter = 0;
#endif

    // Get require keys
    getKey(operatorSeed);
    std::cout << "OperatorAddress: " << nodeIp << ":" << nodePort << "\n";
    std::cout << "OperatorID: " << mOperatorPublicIdentity << "\n";

    // Create verifier instance
    mOcVerifier = (uint8_t *)createOCVerifier();
}

NodeVerifier::~NodeVerifier()
{
    // Stop all threads
    stop();

    // Clean oc verifier
    if (mOcVerifier)
    {
        destroySolVerifier((void *)mOcVerifier);
        mOcVerifier = nullptr;
    }
}

void NodeVerifier::getKey(const char *operatorSeed)
{
    getSubseedFromSeed((unsigned char *)operatorSeed, mOperatorSubSeed);
    getPrivateKeyFromSubSeed(mOperatorSubSeed, operatorPrivateKey);
    getPublicKeyFromPrivateKey(operatorPrivateKey, mOperatorPublicKey);
    getIdentityFromPublicKey(mOperatorPublicKey, mOperatorPublicIdentity, false);
}

RequestedCustomMiningSolutionVerification NodeVerifier::convertFromSolution(const solution &rSolution, bool isValid)
{
    RequestedCustomMiningSolutionVerification respond;
    respond.taskIndex = rSolution.taskIndex;
    respond.nonce = rSolution.combinedNonce;
    respond.encryptionLevel = rSolution.encryptionLevel;
    respond.computorRandom = rSolution.computorRandom;
    respond.reserve2 = rSolution.reserve2;
    respond.isValid = isValid ? 1 : 0;
    return respond;
};

// Add a solution into submitteed queue
int NodeVerifier::addVerifiedSolutions(solution *pSolution, bool isValid)
{
    if (isValid)
    {
        mValidSolutionsCount.fetch_add(1);
    }
    else
    {
        mInvalidSolutionsCount.fetch_add(1);
    }
    mTotalSolutions.fetch_add(1);

    RequestedCustomMiningSolutionVerification verifedSol = convertFromSolution(*pSolution, isValid);
    // Save the solution for sending to node
    {
        std::lock_guard<std::mutex> validLock(mValidSolLock);
        mReportedSolutionsVec.push_back(verifedSol);
    }
    return 0;
}

void NodeVerifier::verifySolutionFromNode(const task &rTask, std::vector<solution> &rSolutions)
{
    task local_task = rTask;
    for (auto &candidate : rSolutions)
    {
        //int computorID = getComputorIDFromSol(&candidate);

        // There is some case that solution need to be decrypt before do the verification
        solution decryptedSolution;
        int decrypt_sts = decryptSolution((uint8_t *)&candidate, sizeof(candidate), nullptr, 0, &decryptedSolution);
        if (decrypt_sts)
        {
            printf("Can not decrypt solution.\n");
            continue;
        }
        uint8_t out[32];
        bool isValid = verify(mOcVerifier, &local_task, &decryptedSolution, out);

        // Dummy test, for each 2 valid solutions, the next one will be invalid
#if TESTNET_ENABLE
        isValid = false;
        {
            std::lock_guard<std::mutex> dummyLock(mDummyLock);
            mDummyCounter++;
            if (mDummyCounter % 4 == 0)
            {
                isValid = true;
            }
        }
#endif
        // Save the solution for sending to node
        addVerifiedSolutions(&candidate, isValid);
    }
}

void NodeVerifier::getCustomMiningSolutions(QCPtr pConnection, const char *logHeader, const std::map<uint64_t, task> &nodeTask)
{
    mNodeSolutions.clear();

    struct
    {
        RequestResponseHeader header;
        RequestedCustomMiningData requestData;
        unsigned char signature[SIGNATURE_SIZE];
    } packet;

    packet.header.setSize(sizeof(packet));
    packet.header.randomizeDejavu();
    packet.header.setType(RequestedCustomMiningData::type);

    for (const auto &it : nodeTask)
    {
        unsigned long long taskIndex = it.second.taskIndex;
        packet.requestData.dataType = RequestedCustomMiningData::solutionType;
        packet.requestData.fromTaskIndex = taskIndex;
        packet.requestData.toTaskIndex = 0; // Unused

        // Sign the message
        uint8_t digest[32] = {0};
        uint8_t signature[64] = {0};
        KangarooTwelve(
            (unsigned char *)&packet.requestData,
            sizeof(RequestedCustomMiningData),
            digest,
            32);
        sign(mOperatorSubSeed, mOperatorPublicKey, digest, signature);
        memcpy(packet.signature, signature, 64);

        // Send request solution
        int dataSent = pConnection->sendData((uint8_t *)&packet, sizeof(packet));
        if (dataSent == sizeof(packet))
        {
            // Get the solution
            RequestResponseHeader respond_header = pConnection->receiveHeader();
            // Verified the message
            if (respond_header.type() == RespondCustomMiningData::type)
            {
                if (respond_header.size() > sizeof(RequestResponseHeader))
                {
                    int dataSize = respond_header.size() - sizeof(RequestResponseHeader);
                    std::vector<unsigned char> dataBuffer(dataSize);
                    unsigned char *pData = &dataBuffer[0];
                    int receivedSize = pConnection->receiveData(pData, dataSize);

                    if (receivedSize != dataSize)
                    {
                        continue;
                    }

                    CustomMiningRespondDataHeader respondDataHeader = *(CustomMiningRespondDataHeader *)pData;
                    if (respondDataHeader.itemCount > 0 && respondDataHeader.respondType == RespondCustomMiningData::solutionType)
                    {
                        std::cout << "Found " << respondDataHeader.itemCount
                                  << " shares for task index " << taskIndex
                                  << std::endl
                                  << std::flush;

                        solution respondSolution;
                        uint8_t *pSolutionData = pData + sizeof(CustomMiningRespondDataHeader);
                        for (int k = 0; k < respondDataHeader.itemCount; k++, pSolutionData += solutionPayloadSize)
                        {
                            memcpy((uint8_t *)&respondSolution + solutionPayloadOffset, pSolutionData, solutionPayloadSize);
                            mNodeSolutions[taskIndex].push_back(respondSolution);
                        }

                        // Verified solutions
                        verifySolutionFromNode(it.second, mNodeSolutions[taskIndex]);
                    }
                }
            }
        }
    }
}

std::vector<unsigned char> NodeVerifier::waitForPackage( QCPtr pConnection, int packageType, int64_t timeOut)
{
    std::vector<unsigned char> dataBuffer;
    auto start = std::chrono::system_clock::now();
    const auto timeout = std::chrono::milliseconds(timeOut);
    while (true)
    {
        // Check timeout
        if (std::chrono::system_clock::now() - start > timeout) 
        {
            std::cout << "Timeout: did not receive packet type " << packageType << std::endl << std::flush;
            break;
        }

        // Get the task
        RequestResponseHeader respond_header = pConnection->receiveHeader();
        
        // Empty or malfunction package just skip
        if (respond_header.size() <= sizeof(RequestResponseHeader))
        {
            continue;
        }

        // Payload
        unsigned int dataSize = respond_header.size() - sizeof(RequestResponseHeader);
        dataBuffer.resize(dataSize);
        unsigned char *pData = &dataBuffer[0];
        int receivedSize = pConnection->receiveData(pData, dataSize);

        // Expected header process and break
        if ((int)respond_header.type() == packageType)
        {
            // Data is failed to rev
            if (receivedSize != dataSize)
            {
                std::cout << "Respond size is mismatched!\n";
                dataBuffer.clear();
            }
            return dataBuffer;
        }
    }

    return dataBuffer;
}

bool NodeVerifier::fetchCustomMiningData(QCPtr pConnection, const char *logHeader)
{
    mNodeTasks.clear();
    struct
    {
        RequestResponseHeader header;
        RequestedCustomMiningData requestData;
        unsigned char signature[SIGNATURE_SIZE];
    } packet;

    packet.header.setSize(sizeof(packet));
    packet.header.randomizeDejavu();
    packet.header.setType(RequestedCustomMiningData::type);

    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();

    uint64_t fromTaskIndex = (uint64_t)(milliseconds - TIME_WINDOWS_OFFSET_IN_MS);
    uint64_t toTaskIndex = 0; // Fetch all the task from the fromTaskIndex
    packet.requestData.dataType = RequestedCustomMiningData::taskType;
    packet.requestData.fromTaskIndex = fromTaskIndex;
    packet.requestData.toTaskIndex = toTaskIndex;

    // Sign the message
    uint8_t digest[32] = {0};
    uint8_t signature[64] = {0};
    KangarooTwelve(
        (unsigned char *)&packet.requestData,
        sizeof(RequestedCustomMiningData),
        digest,
        32);
    sign(mOperatorSubSeed, mOperatorPublicKey, digest, signature);
    memcpy(packet.signature, signature, 64);

    // Send request all task
    int dataSent = pConnection->sendData((uint8_t *)&packet, sizeof(packet));
    if (dataSent == sizeof(packet))
    {
        std::vector<unsigned char> dataBuffer = waitForPackage( pConnection, (int)RespondCustomMiningData::type, 10000);
        if (!dataBuffer.empty())
        {
            uint8_t* pData = &dataBuffer[0];
            unsigned long long lastReceivedTaskTs = 0;
            CustomMiningRespondDataHeader respondDataHeader = *(CustomMiningRespondDataHeader *)pData;
            if (respondDataHeader.itemCount > 0 && respondDataHeader.respondType == RespondCustomMiningData::taskType)
            {
                std::vector<task> taskVec;
                task respondTask;
                uint8_t *pTaskData = pData + sizeof(CustomMiningRespondDataHeader);
                for (int i = 0; i < respondDataHeader.itemCount; i++, pTaskData += taskPayloadSize)
                {
                    memcpy((uint8_t *)&respondTask + taskPayloadOffset, pTaskData, taskPayloadSize);
                    mNodeTasks[respondTask.taskIndex] = respondTask;
                }

                for (auto it = mNodeTasks.begin(); it != mNodeTasks.end(); ++it)
                {
                    lastReceivedTaskTs = std::max((unsigned long long)it->first, lastReceivedTaskTs);
                }

                // From current active task. Try to fetch solutions/shares of the task
                getCustomMiningSolutions(pConnection, logHeader, mNodeTasks);
            }
        }
    }

    return !mNodeTasks.empty();
}

void NodeVerifier::getSolutionsThread()
{
    auto startTime = std::chrono::system_clock::now();

    QCPtr qc;
    bool needReconnect = true;
    std::string log_header = "[OP:" + mNodeIP + "]: ";
    mIsRunning = true;
    while (mIsRunning)
    {
        try
        {
            if (needReconnect)
            {
                needReconnect = false;
                qc = make_qc(mNodeIP.c_str(), mNodePort);

                startTime = std::chrono::system_clock::now();
                std::cout<< log_header << "Connected/Reconnected to OPERATOR node " <<  mNodeIP.c_str() << std::endl;
            }

            // Fetch tasks and solution from node
            fetchCustomMiningData(qc, log_header.c_str());

            // Report verified solutions if there is any
            reportVerifiedSol(qc);

            std::this_thread::sleep_for(std::chrono::milliseconds(1000));

            // Check timeout
            if (NODE_CONNECTION_TIMEOUT > 0 &&
                std::chrono::system_clock::now() - startTime > std::chrono::milliseconds(NODE_CONNECTION_TIMEOUT)) 
            {
                needReconnect = true;
            }

        }
        catch (std::logic_error &ex)
        {
            std::cout<< ex.what() << std::endl;
            fflush(stdout);
            needReconnect = true;
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
        catch (...)
        {
            std::cout<< "Unknown exception caught!\n";
            fflush(stdout);
            needReconnect = true;
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
    }
}

bool NodeVerifier::reportVerifiedSol(QCPtr pConnection)
{
    bool haveSolsToReport = false;
    RequestedCustomMiningSolutionVerification verifiedSol;
    bool isTimeOut = false;
    auto start = std::chrono::system_clock::now();

    while (mIsRunning && !mReportedSolutionsVec.empty() && !isTimeOut)
    {
        {
            std::lock_guard<std::mutex> validLock(mValidSolLock);
            if (!mReportedSolutionsVec.empty())
            {
                verifiedSol = mReportedSolutionsVec.front();
                haveSolsToReport = true;
            }
        }

        // Submit the validated solutions
        if (haveSolsToReport)
        {
            struct
            {
                RequestResponseHeader header;
                RequestedCustomMiningSolutionVerification verifiedSol;
                uint8_t signature[SIGNATURE_SIZE];
            } packet;

            // Header
            packet.header.setSize(sizeof(packet));
            packet.header.randomizeDejavu();
            packet.header.setType(RequestedCustomMiningSolutionVerification::type);

            // Payload
            packet.verifiedSol = verifiedSol;

            // Sign the message
            uint8_t digest[32] = {0};
            uint8_t signature[64] = {0};
            KangarooTwelve(
                (unsigned char *)&packet.verifiedSol,
                sizeof(packet.verifiedSol),
                digest,
                32);
            sign(mOperatorSubSeed, mOperatorPublicKey, digest, signature);
            memcpy(packet.signature, signature, 64);

            // Send data
            int dataSent = pConnection->sendData((uint8_t *)&packet, sizeof(packet));

            // Send successfull, erase it from the invalid queue
            if (dataSent == sizeof(packet))
            {
                struct
                {
                    RequestResponseHeader header;
                    RespondCustomMiningSolutionVerification verifiedSol;
                } respondPacket;

                int dataRev = pConnection->receiveData((uint8_t *)&respondPacket, sizeof(respondPacket));
                if (dataRev > 0)
                {
                    // TODO: process respond here.
                }

                // Repsond is good. Remove the submitted sol
                std::lock_guard<std::mutex> validLock(mValidSolLock);
                if (!mReportedSolutionsVec.empty())
                {
                    mReportedSolutionsVec.erase(mReportedSolutionsVec.begin());
                    mSubmittedSolutionsCount.fetch_add(1);
                }
            }
        }

        auto end = std::chrono::system_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        isTimeOut = elapsed > REPORTED_TIMEOUT_IN_MS;
        if (isTimeOut)
        {
            std::cout << "Submitted timeout " << elapsed << " ms\n";
        }
    }
    return haveSolsToReport;
}

void NodeVerifier::printStats()
{
    std::stringstream statStr;
    statStr << "Valid: " << mValidSolutionsCount.load()
            << " | Invalid: " << mInvalidSolutionsCount.load()
            << " | Total: " << mTotalSolutions.load()
            << " | Submit: " << mSubmittedSolutionsCount.load();
    std::cout << "NodeVerifier - " << statStr.str() << std::endl;
}

int NodeVerifier::launch()
{
    // Trigger thread
    mVerifierThread = std::make_unique<std::thread>(&NodeVerifier::getSolutionsThread, this);

    return 0;
}

int NodeVerifier::stop()
{
    mIsRunning = false;

    // Wait for thread join
    if (mVerifierThread && mVerifierThread->joinable())
    {
        mVerifierThread->join();
        mVerifierThread = nullptr;
    }
    return 0;
}

std::unique_ptr<NodeVerifier> pNodeVerifier = nullptr;
int launchNodeVerifier(const char *nodeIp, int nodePort, const char *operatorSeed)
{
    pNodeVerifier = nullptr;
    pNodeVerifier.reset(new NodeVerifier(nodeIp, nodePort, operatorSeed));
    int sts = pNodeVerifier->launch();
    return sts;
}

int stopNodeVerifier()
{
    std::cout << "Stop node verifier!\n";
    int sts = 0;
    if (pNodeVerifier)
    {
        sts = pNodeVerifier->stop();
    }
    return sts;
}

int addVerifiedSolutions(void *pSolution, bool isValid)
{
    int sts = 0;
    if (pNodeVerifier)
    {
        sts = pNodeVerifier->addVerifiedSolutions((solution *)pSolution, isValid);
    }
    return sts;
}

void printNodeVerifierStats()
{
    if (pNodeVerifier)
    {
        pNodeVerifier->printStats();
    }
}