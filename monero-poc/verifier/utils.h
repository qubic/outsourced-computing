#pragma once

#include <random>
#include <fstream> // Required for ifstream

static bool fileExists(const std::string& filename)
{
    std::ifstream file(filename); // Try to open the file
    return file.good();          // Check if the file stream is in a "good" state
}

static void byteToHex(const uint8_t* byte, char* hex, const int sizeInByte)
{
    for (int i = 0; i < sizeInByte; i++){
        sprintf(hex+i*2, "%02x", byte[i]);
    }
}
static void hexToByte(const char* hex, uint8_t* byte, const int sizeInByte)
{
    for (int i = 0; i < sizeInByte; i++){
        sscanf(hex+i*2, "%2hhx", &byte[i]);
    }
}

static void rand32(uint32_t* r) {
    std::random_device rd;
    static thread_local std::mt19937 generator(rd());
    std::uniform_int_distribution<uint32_t> distribution(0,UINT32_MAX);
    *r = distribution(generator);
}

static void rand64(uint64_t* r) {
    static thread_local std::mt19937 generator;
    std::uniform_int_distribution<uint64_t> distribution(0,UINT32_MAX);
    *r = distribution(generator);
}

static long long secondsSinceEpoch(int year, int month, int day, int hour, int minute, int second) {
    std::tm t{};
    t.tm_year = year - 1900; // Year since 1900
    t.tm_mon = month - 1;   // Month (0-11)
    t.tm_mday = day;        // Day of the month (1-31)
    t.tm_hour = hour;       // Hour (0-23)
    t.tm_min = minute;      // Minute (0-59)
    t.tm_sec = second;      // Second (0-59)
    t.tm_isdst = 0;         // Not daylight saving time

    std::time_t timeSinceEpoch = std::mktime(&t);
    if (timeSinceEpoch == -1) {
        return -1; // Indicate an error
    }
    return static_cast<long long>(timeSinceEpoch);
}

static int getCurrentEpoch()
{
    int year = 2022;
    int month = 4;
    int day = 13;
    int hour = 12;
    int minute = 0;
    int second = 0;

    long long referenceEpoch = secondsSinceEpoch(year, month, day, hour, minute, second);
    if (referenceEpoch == -1) {
        return -1; // Exit with an error code
    }

    auto now = std::chrono::system_clock::now();
    auto nowEpoch = std::chrono::system_clock::to_time_t(now);
    long long current = static_cast<long long>(nowEpoch);

    long long differenceInSeconds = current - referenceEpoch;
    return differenceInSeconds / (3600*24*7);
}