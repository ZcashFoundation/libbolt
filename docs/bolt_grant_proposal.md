Implmentation of Blind Off-Chain Lightweight Transactions (BOLT)
=========================

Zcash Foundation Grant Proposal

J. Ayo Akinyele, <ayo@yeletech.org>

Motivation and Overview
=======================

​BOLT is a system for conducting privacy-preserving off-chain payments between
pairs of individual parties. BOLT is designed to provide a "Layer 2" payment protocol for privacy-preserving cryptocurrencies such as ZCash, by allowing individuals to establish and use payment channels for rapid/instantaneous payments that do not require an on-chain transaction. 

BOLT currently exists as a specification and proof of concept implementation partially in Charm by Ian Miers and Matthew Green (the original authors of the BOLT protocol). The goal in this effort is to develop a production quality implementation of BOLT in the Rust programming language (a memory-safe and type-safe language that improves security by preventing common low-level bugs). The project is intended to be released as open source to benefit the Zcash ecosystem and further the broader goals of addressing the scalability problems of cryptocurrencies like Zcash and beyond.


Technical Approach
=================

​The initial work will focus on the development of the Bolt library (or libbolt) and the core cryptographic components of the BOLT protocol. Specifically, libbolt will include routines for constructing and parsing the messages required for interactive off-chain transactions with (one or more) remote BOLT participant(s), and will provide necessary routines that can interface with the cryptocurrency node (e.g., Zcash) via its interface.
​
Libbolt will include the implementation of both the unidirectional payment scheme as well as the bidirectional payment construction. This includes an implementation of the routines necessary to execute the two interactive protocols, Establish and Pay. 

This library will be implemented initially in Rust and then will explore a Go implementation for the second phase. The Rust implementation will leverage the bn pairing library provided by Sean Bowe (Zcash Engineer). In terms of efficiency, we will also explore optimizations described in the original paper with respect to the NIZK proofs in the Pay protocol. In addition, we will write unit tests and produce a design document for libbolt that describes the details of the cryptographic instantiations for the core primitives and zero-knowledge proofs of knowledge statements. 

Background and Qualifications
=============================

I received a Ph.D. in Computer Science from Johns Hopkins University (JHU) in 2013 specializing in applied cryptography. In 2007, earned an M.S. in Software Engineering from Carnegie Mellon University specializing in Information Technology. In 2006, obtained a B.S. in Computer Science from Bowie State University.

In terms of qualifications, a majority of my work is cryptographic engineering related and I've contributed to a number of open source projects as a result. In particular, I am the main developer behind the following open source projects:

- Charm-Crypto: a rapid prototyping framework for advanced cryptosystems. Written in Python/C and used extensively by academic researchers and practicioners around the world. Link: https://github.com/jhuisi/charm

- OpenABE: a new commercial-grade open source attribute-based encryption library. Written in C/C++ and will be available soon at https://github.com/zeutro/openabe.


Evaluation Plan
===============
We anticipate five milestones that mirror the technical approach described earlier:

1. Produce a design document that describes libbolt design and primitive choices. In addition, the document will expand on the NIZKP statements and interatctive protocols for generating blind signatures and so on.
2. Implement in Rust the core cryptographic building blocks required by libbolt -- Commitment scheme, Signatures with efficient protocols, Symmetric key Encryption, etc.
3. Fully implement in Rust the bidirectional payment construction -- including the establish and pay interactive protocols. Write unit tests and document how to use the APIs.
4. Explore optimizations for the range proofs in the Pay protocol.
5. Fully implement in Rust the unidirectional payment construction. Write unit tests and document how to use the APIs.

Security Considerations
=======================

The security implications of this project is to mitigate the bottleneck of on-chain transactions on the Zcash network. With off-chain transactions, the BOLT protocol dramatically reduces the transaction volume arriving at the Zcash blockchain without adding new trusted centralized entities.

Schedule
========

Task 1 & 2: May 15, 2018 - These two tasks will be done in parallel and the design document will be reviewed by Ian Miers and Matthew Green.

Task 3: June 15, 2018 - Will deliver the bidirectional payment construction implementation along with unit tests.

Task 4: July 1, 2018 - Will explore optimizations for the range proofs with assistance from Ian Miers. Will refine the design document accordingly.

Task 5: July 31, 2018 - Will deliver the unidirectional payment construction implementation along with unit tests. Note that the unidirectional construction is considerably more complex than the bidirectional construction and thus may take longer.


Budget and Justification
========================

To ensure a high-quality implementation, I am estimating a budget of $30k to support the development of libbolt in Rust and exploring a possible Go implementation. This budget reflects compensation of my effort over a three month period dedicated to this project.