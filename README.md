# API Assessment Solution

## Overview

This repository contains my solution for the API Assessment.

The assessment consisted of four layers:

1. Fetch the complete encrypted dataset and prove byte-level integrity.
2. Decrypt the dataset using a platform-issued key.
3. Identify the hidden algorithm answer from the decrypted records.
4. Provide qualitative analysis of the dataset and platform design.

---

## Environment

Python Version: 3.12

Dependencies:

* requests
* python-dotenv
* cryptography

Installation:

```bash
pip install -r requirements.txt
```

---

## Layer 1 – Dataset Retrieval and Integrity Validation

### Discovery Process

* Identified dataset endpoint.
* Examined response headers.
* Discovered batch retrieval endpoint through the HTTP Link header.
* Retrieved all 500 records using five batch requests.

### Integrity Validation

Several SHA-256 strategies were evaluated:

* Concatenated Base64 records
* Newline-separated records
* JSON serialization
* Pretty JSON serialization
* Decoded encrypted byte stream

The correct integrity proof was obtained by:

1. Base64-decoding every encrypted record.
2. Concatenating the encrypted bytes in dataset order.
3. Computing SHA-256 over the resulting byte stream.

Layer 1 was successfully accepted using this hash.

---

## Layer 2 – Decryption

### Discovery

The platform-issued private key was discovered through endpoint exploration.

### Decryption Approach

* Loaded the RSA private key.
* Base64-decoded each encrypted record.
* Applied RSA decryption.
* Reconstructed the decrypted dataset.

### Validation

Computed SHA-256 over the decrypted content and submitted as `decrypted_hash`.

---

## Layer 3 – Hidden Answer

The decrypted dataset was analyzed to identify the required alphabetic answer.

The analysis involved:

* Parsing decrypted records.
* Inspecting record structure.
* Evaluating embedded patterns and metadata.
* Extracting the final answer according to platform requirements.

---

## Layer 4 – Analysis

Key observations:

* Integrity verification is performed on canonical encrypted bytes rather than transport encoding.
* Link headers advertise optimized retrieval mechanisms.
* Cryptographic separation between integrity and decryption demonstrates defense-in-depth.
* Error messages intentionally provide discoverability hints.
* The assessment rewards systematic exploration and protocol reasoning over brute force approaches.

---

## Lessons Learned

* HTTP headers can contain critical discovery information.
* Integrity checks must be performed on canonical representations.
* Structured exploration is more effective than endpoint guessing.
* Cryptographic workflows should be validated incrementally.
