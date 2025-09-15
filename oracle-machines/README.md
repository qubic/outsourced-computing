# Qubic - Oracle Machines
<!-- TOC -->

- [Qubic - Oracle Machines](#qubic---oracle-machines)
    - [Purpose](#purpose)
    - [How It Works](#how-it-works)
    - [Key Characteristics](#key-characteristics)
    - [Example Use Cases](#example-use-cases)
    - [Why It Matters](#why-it-matters)

<!-- /TOC -->

## Purpose

Oracle Machines (OM) allow Qubic to access information from the outside world (prices, validations, data feeds, etc.). They are the bridge between on-chain smart contracts and off-chain services.

## How It Works

1. Trigger – A query is sent, either by a user (manual) or a smart contract (automated).
2. Bridge (Extra Node) – Converts the query into a standard format (like a web request) and forwards it to the external oracle.
3. External Oracle – Provides the requested data (e.g. “price of DOGE”).
4. Computors (Qubic validators) – Independently check and publish the reply.
5. Validation – If 451+ computors agree on the same answer, the result is accepted.
6. Result – Returned to the user or smart contract as success or failure.

## Key Characteristics

- Reliable: Requires 451 identical replies to avoid manipulation.
- Flexible: Works for both user queries and smart contracts.
- Independent: External services do not need to know about Qubic.
- Transparent: Users can track query status (pending, cancelled, result).
- Incentivized: Computors who provide valid replies receive the donation.

## Example Use Cases

1. User Request: Validate a DOGE share before accepting it.
2. Smart Contract Request: Fetch the current DOGE price for an automated trade.

## Why It Matters

Oracle Machines unlock real-world use cases for Qubic by bringing trusted external data on-chain.
They are essential for DeFi, cross-chain validation, and automated decision-making within smart contracts.