import requests
import hashlib
import json
import base64
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
from Crypto.Hash import SHA256, SHA1

BASE_URL = "https://ca-seassessment-api-dev.happywater-190f264d.northcentralus.azurecontainerapps.io"
API_KEY  = ""  # ← paste your key

HEADERS  = {"Authorization": f"Bearer {API_KEY}"}

# ─────────────────────────────────────────────
# STEP 1 — Fetch the private key
# ─────────────────────────────────────────────
print("="*60)
print("STEP 1: Fetching private key...")
print("="*60)

r           = requests.get(f"{BASE_URL}/api/v1/private-key", headers=HEADERS)
private_pem = r.text
print(f"Status: {r.status_code}")
print(f"Key preview: {private_pem[:100]}...")

# Save key to file
with open("private_key.pem", "w") as f:
    f.write(private_pem)
print("Saved to private_key.pem")

# Load the RSA key
private_key = RSA.import_key(private_pem)
print(f"RSA key size: {private_key.size_in_bits()} bits")

# ─────────────────────────────────────────────
# STEP 2 — Fetch all 500 encrypted records
# ─────────────────────────────────────────────
print("\n" + "="*60)
print("STEP 2: Fetching all 500 records...")
print("="*60)

all_records = []
page        = 1

while True:
    r    = requests.get(
        f"{BASE_URL}/api/v1/dataset",
        headers=HEADERS,
        params={"page": page, "page_size": 25}
    )
    body = r.json()
    recs = body.get("data", [])
    all_records.extend(recs)
    print(f"Page {page}: {len(recs)} records | Total: {len(all_records)} | Rate remaining: {r.headers.get('ratelimit-remaining', 'N/A')}")

    if not body.get("has_more"):
        break

    remaining = int(r.headers.get("ratelimit-remaining", 5))
    if remaining <= 1:
        reset = int(r.headers.get("ratelimit-reset", 2))
        print(f"Rate limit low. Sleeping {reset+1}s...")
        time.sleep(reset + 1)
    else:
        time.sleep(0.3)

    page += 1

print(f"\nTotal records fetched: {len(all_records)}")

# ─────────────────────────────────────────────
# STEP 3 — Decrypt using RSA private key
# ─────────────────────────────────────────────
print("\n" + "="*60)
print("STEP 3: Decrypting records with RSA private key...")
print("="*60)

decrypted_records = []
failed            = 0

for i, record in enumerate(all_records):
    raw = base64.b64decode(record)

    # Try OAEP with SHA-256 (most common modern)
    try:
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        plain  = cipher.decrypt(raw).decode("utf-8")
        decrypted_records.append(plain)
        if i < 5:
            print(f"  Record {i} (OAEP/SHA256): {plain[:150]}")
        continue
    except Exception as e1:
        pass

    # Try OAEP with SHA-1 (older default)
    try:
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA1)
        plain  = cipher.decrypt(raw).decode("utf-8")
        decrypted_records.append(plain)
        if i < 5:
            print(f"  Record {i} (OAEP/SHA1): {plain[:150]}")
        continue
    except Exception as e2:
        pass

    # Try PKCS1 v1.5
    try:
        cipher = PKCS1_v1_5.new(private_key)
        plain  = cipher.decrypt(raw, None)
        if plain:
            text = plain.decode("utf-8")
            decrypted_records.append(text)
            if i < 5:
                print(f"  Record {i} (PKCS1v1.5): {text[:150]}")
            continue
    except Exception as e3:
        pass

    # All failed
    if i < 5:
        print(f"  Record {i}: ALL methods failed")
    decrypted_records.append(None)
    failed += 1

success = [d for d in decrypted_records if d]
print(f"\nDecrypted: {len(success)}/{len(all_records)} | Failed: {failed}")

# ─────────────────────────────────────────────
# STEP 4 — Save decrypted records
# ─────────────────────────────────────────────
print("\n" + "="*60)
print("STEP 4: Saving and analyzing decrypted records...")
print("="*60)

with open("decrypted_records.json", "w") as f:
    json.dump(decrypted_records, f, indent=2)
print("Saved to decrypted_records.json")

# Show samples
print("\nFirst 5 decrypted records:")
for i, rec in enumerate(decrypted_records[:5]):
    print(f"  [{i}]: {rec}")

# ─────────────────────────────────────────────
# STEP 5 — Compute decrypted hash (Layer 2)
# ─────────────────────────────────────────────
print("\n" + "="*60)
print("STEP 5: Computing Layer 2 hash...")
print("="*60)

valid   = [d for d in decrypted_records if d]
compact = json.dumps(valid, separators=(',', ':')).encode('utf-8')
hash1   = hashlib.sha256(compact).hexdigest()

pretty  = json.dumps(valid, indent=2).encode('utf-8')
hash2   = hashlib.sha256(pretty).hexdigest()

joined  = "\n".join(valid).encode('utf-8')
hash3   = hashlib.sha256(joined).hexdigest()

print(f"SHA-256 compact JSON : {hash1}")
print(f"SHA-256 pretty JSON  : {hash2}")
print(f"SHA-256 newline join : {hash3}")

print(f"\n{'='*60}")
print("LAYER 2 SUBMISSION:")
print(f"{'='*60}")
print(json.dumps({
    "type": "decrypted_hash",
    "value": hash1,
    "notes": "SHA-256 of RSA-decrypted records, compact JSON"
}, indent=2))

# ─────────────────────────────────────────────
# STEP 6 — Find hidden word (Layer 3)
# ─────────────────────────────────────────────
print("\n" + "="*60)
print("STEP 6: Searching for hidden word (Layer 3)...")
print("="*60)

# Try parsing as JSON
parsed = []
for rec in decrypted_records:
    if rec:
        try:
            parsed.append(json.loads(rec))
        except:
            parsed.append({"raw": rec})

if parsed:
    sample = parsed[0]
    print(f"Record structure: {json.dumps(sample, indent=2)}")
    print(f"Fields: {list(sample.keys()) if isinstance(sample, dict) else 'not a dict'}")

    if isinstance(sample, dict):
        # Method 1: first letter of each record's first field value
        for field in sample.keys():
            letters = ""
            for rec in parsed:
                if isinstance(rec, dict):
                    val = str(rec.get(field, ""))
                    if val:
                        letters += val[0]
            if letters.replace(" ", "").isalpha():
                print(f"\nFirst letter of '{field}': {letters}")

        # Method 2: look for single-char fields
        for field, val in sample.items():
            if isinstance(val, str) and len(val) == 1 and val.isalpha():
                chars = "".join(str(r.get(field, "")) for r in parsed if isinstance(r, dict))
                print(f"\nSingle-char field '{field}': {chars}")

        # Method 3: look for suspicious field names
        for field in ["letter", "char", "hidden", "secret", "flag", "code", "token", "symbol"]:
            if field in sample:
                vals = [str(r.get(field, "")) for r in parsed if isinstance(r, dict)]
                print(f"\nSuspect field '{field}': {''.join(vals)}")