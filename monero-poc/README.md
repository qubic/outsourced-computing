# Qubic - Monero POC
<!-- TOC -->

- [Qubic - Monero POC](#qubic---monero-poc)
  - [Highlevel Process Description](#highlevel-process-description)
  - [QUBIC's Monero Wallet Address](#qubics-monero-wallet-address)
  - [POC Phases](#poc-phases)
  - [The Principle](#the-principle)
    - [What Monero mining software to be used?](#what-monero-mining-software-to-be-used)
    - [How to receive a task?](#how-to-receive-a-task)
    - [How to send back a solution?](#how-to-send-back-a-solution)

<!-- /TOC -->


## Highlevel Process Description
![Qubic - Outsourced Computing Highlevel Monero POC Process FlowChart](images/QubicOutsourcedComputing_MoneroPOC_v2.png)

[Click here for PDF](images/QubicOutsourcedComputing_MoneroPOC_v2.pdf)

## QUBIC's Monero Wallet Address
```
8C5gopBP7uHNjPPZWhgUVCSe3s2dy4DLjZRgwhMp8DLpPoXTU5epY2VMKP1Vnc5dwJJ9QDCiKbMjberggTu3qYWiGMYFHzd
```

## POC Phases
The POC is junked into Phases.

1. Basic Testing of Messaging ✅
2. Connect Qubic Messaging with Monero (Bridging)✅
3. End-To-End Messaging (including signaling and real monero tasks) ✅
4. Solution Validation (Oracle) and Revenue Calculation ✅
5. Final Test Round ⏳
6. Go-Live

## The Principle
For the POC we need high speed delivery of tasks and solutions. We will build on top of the [Qubic Broadcast Message](https://github.com/qubic/core/blob/main/src/network_messages/broadcast_message.h) to achieve this.

Threfore we introduce two new message types:
1. `#define MESSAGE_TYPE_CUSTOM_MINING_TASK 1`
2. `#define MESSAGE_TYPE_CUSTOM_MINING_SOLUTION 2`

1. Custom Mining Task
This type is used by ARB to send out a Task. The interval between tasks is dynamic and may vary from a few seconds up to a few 10s of seconds.

**The Task struct**
```c++
struct
{
    unsigned int sizeAndType;
    unsigned int dejavu;

    unsigned char sourcePublicKey[32]; // the source public key is the DISPATCHER public key
    unsigned char zero[32];  // empty/zero 0
    unsigned char gammingNonce[32];

    unsigned long long taskIndex; // ever increasing number (unix timestamp in ms)

    unsigned short firstComputorIndex, lastComputorIndex; // range of computors to which this task is meant to
    unsigned int padding;

    unsigned char m_blob[408]; // Job data from pool
    unsigned long long m_size;  // length of the blob
    unsigned long long m_target; // Pool difficulty
    unsigned long long m_height; // Block height
    unsigned char m_seed[32]; // Seed hash for XMR

    unsigned char signature[64];
} task;
```

> [!Note]
> The shared key for Destination=0 is all-zeros

To verify the message, please refer to https://github.com/qubic/core/blob/main/src/qubic.cpp#L474
To find the message type, please refer to https://github.com/qubic/core/blob/main/src/qubic.cpp#L555


2. Custom Mining Solution
After Processing the Task and generating the solution. The solution needs to be sent back to the network.

**The Solution struct**
```c++
struct
{
    unsigned int sizeAndType;
    unsigned int dejavu;

    unsigned char sourcePublicKey[32];
    unsigned char zero[32]; // empty/zero 0
    unsigned char gammingNonce[32];

    unsigned long long taskIndex; // sohuld match the index from task
    unsigned short firstComputorIndex, lastComputorIndex; // copy & paste from task

    unsigned int nonce;         // xmrig::JobResult.nonce
    unsigned int padding;       // reserve for future use
    unsigned char result[32];   // xmrig::JobResult.result

    unsigned char signature[64];
} solution;
```

>[!CAUTION]
> The Above structs already contain the [RequestResponseHeader](https://github.com/qubic/core/blob/main/src/network_messages/header.h).

### What Monero mining software to be used?
For the POC we gonna try with [XMRig](https://xmrig.com/). If you want to user your own. Feel free to do so.

### How to receive a task?
Connect to the network and listen for the packet type `BROADCAST_MESSAGE (1)`.

Identify a Task:
1. The source must be [DISPATCHER](https://github.com/qubic/core/blob/main/src/public_settings.h#L60)
2. Verify Signature
3. Check the Message type (sample: https://github.com/qubic/core/blob/main/src/qubic.cpp#L555)
4. Verify `taskIndex` is higher than previous loaded task

If the above match, use that task and proceed with solution finding.

### How to send back a solution?
If you have found a solution, pack it into the solution struct.

- `sourcePublicKey` must be your computor public key
- `taskIndex` must be the task indes from recevied task
- `nonce` must be the xmrig::JobResult.nonce and equal to a `value` such that `firstComputorIndex + nonce % (676 / task.NumberOfUpstreams) == computorIndex`
- `result` must be the result from xmrig::JobResult.result

Sign your solution packet with your computor seed. make the `dejavu = 0` to allow propagation of your solution in the network.

