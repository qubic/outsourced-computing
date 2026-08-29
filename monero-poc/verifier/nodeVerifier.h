#pragma once

// Lauch a verifier that connect to node try to fetch solution and submit verified result back to node
int launchNodeVerifier(const char* nodeIp, int nodePort, const char* operatorSeed);

// Stop the node verifier
int stopNodeVerifier();

// Add external verified solutions into submitted queue
int addVerifiedSolutions(void* pSolution, bool isValid);

void printNodeVerifierStats();