
import requests
import hashlib
import json
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────
BASE_URL = "https://ca-seassessment-api-dev.happywater-190f264d.northcentralus.azurecontainerapps.io"
API_KEY  = "sa_28fc52219cd15afe6dce59682df2ed62a2477e78b41476b545c84b1766be71ab"   # ← paste your full sa_... key here

HEADERS  = {"Authorization": f"Bearer {API_KEY}"}

# ─────────────────────────────────────────────
# STEP 1 — Fetch one encrypted record
# ─────────────────────────────────────────────
print("="*60)
print("STEP 1: Fetching one encrypted record...")
print("="*60)

r       = requests.get(f"{BASE_URL}/api/v1/dataset", headers=HEADERS, params={"page": 1, "page_size": 1})
record  = r.json()["data"][0]
print(f"Encrypted record:\n{record}\n")

# ─────────────────────────────────────────────
# STEP 2 — Derive key candidates from API key
# ─────────────────────────────────────────────
print("="*60)
print("STEP 2: Deriving key candidates from API key...")
print("="*60)

api_key_bytes = API_KEY.encode("utf-8")

key_candidates = {
    "SHA-256 of full API key (32 bytes)":
        hashlib.sha256(api_key_bytes).digest(),

    "SHA-256 of API key without prefix (32 bytes)":
        hashlib.sha256(API_KEY.replace("sa_", "").encode()).digest(),

    "MD5 of full API key (16 bytes)":
        hashlib.md5(api_key_bytes).digest(),

    "MD5 of API key without prefix (16 bytes)":
        hashlib.md5(API_KEY.replace("sa_", "").encode()).digest(),

    "First 32 bytes of API key (padded)":
        api_key_bytes[:32].ljust(32, b'\0'),

    "First 16 bytes of API key (padded)":
        api_key_bytes[:16].ljust(16, b'\0'),

    "Hex decode of API key suffix (if hex)":
        None,  # handled below
}

# Try hex decode of the part after sa_
suffix = API_KEY.replace("sa_", "")
try:
    if len(suffix) >= 32:
        key_candidates["Hex decoded suffix (first 32 bytes)"] = bytes.fromhex(suffix[:64])
    if len(suffix) >= 16:
        key_candidates["Hex decoded suffix (first 16 bytes)"] = bytes.fromhex(suffix[:32])
except Exception:
    pass

# Remove None entries
key_candidates = {k: v for k, v in key_candidates.items() if v is not None}

for name, key in key_candidates.items():
    print(f"  {name}: {key.hex()}")

# ─────────────────────────────────────────────
# STEP 3 — Try each key with AES-CBC and AES-GCM
# ─────────────────────────────────────────────
print("\n" + "="*60)
print("STEP 3: Attempting decryption with each key...")
print("="*60)

raw_bytes = base64.b64decode(record)
print(f"Raw bytes length : {len(raw_bytes)}")
print(f"First 32 bytes   : {raw_bytes[:32].hex()}\n")

success = False

for name, key in key_candidates.items():
    # Only try valid AES key sizes
    if len(key) not in (16, 24, 32):
        print(f"  SKIP (invalid key size {len(key)}) → {name}")
        continue

    # Try AES-CBC (IV = first 16 bytes)
    try:
        iv         = raw_bytes[:16]
        ciphertext = raw_bytes[16:]
        cipher     = AES.new(key, AES.MODE_CBC, iv)
        plain      = unpad(cipher.decrypt(ciphertext), AES.block_size)
        text       = plain.decode("utf-8")
        print(f"  ✓ AES-CBC SUCCESS → {name}")
        print(f"    Decrypted: {text[:200]}")
        success = True
    except Exception as e:
        print(f"  ✗ AES-CBC failed → {name}: {e}")

    # Try AES-GCM (nonce = first 12 bytes)
    try:
        nonce      = raw_bytes[:12]
        tag        = raw_bytes[12:28]
        ciphertext = raw_bytes[28:]
        cipher     = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plain      = cipher.decrypt_and_verify(ciphertext, tag)
        text       = plain.decode("utf-8")
        print(f"  ✓ AES-GCM SUCCESS → {name}")
        print(f"    Decrypted: {text[:200]}")
        success = True
    except Exception as e:
        print(f"  ✗ AES-GCM failed → {name}: {e}")

# ─────────────────────────────────────────────
# STEP 4 — If success, decrypt all 500 records
# ─────────────────────────────────────────────
if success:
    print("\n" + "="*60)
    print("STEP 4: Decrypting all 500 records...")
    print("="*60)

    # Find winning key
    winning_key  = None
    winning_mode = None
    winning_name = None

    for name, key in key_candidates.items():
        if len(key) not in (16, 24, 32):
            continue
        try:
            iv         = raw_bytes[:16]
            cipher     = AES.new(key, AES.MODE_CBC, iv)
            plain      = unpad(cipher.decrypt(raw_bytes[16:]), AES.block_size)
            plain.decode("utf-8")
            winning_key  = key
            winning_mode = "CBC"
            winning_name = name
            break
        except:
            pass
        try:
            nonce  = raw_bytes[:12]
            tag    = raw_bytes[12:28]
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            plain  = cipher.decrypt_and_verify(raw_bytes[28:], tag)
            plain.decode("utf-8")
            winning_key  = key
            winning_mode = "GCM"
            winning_name = name
            break
        except:
            pass

    if winning_key:
        print(f"Using: {winning_name} (AES-{winning_mode})")

        all_decrypted = []
        page = 1
        while True:
            resp    = requests.get(
                f"{BASE_URL}/api/v1/dataset",
                headers=HEADERS,
                params={"page": page, "page_size": 25}
            )
            body    = resp.json()
            records = body.get("data", [])

            for rec in records:
                raw = base64.b64decode(rec)
                try:
                    if winning_mode == "CBC":
                        cipher = AES.new(winning_key, AES.MODE_CBC, raw[:16])
                        plain  = unpad(cipher.decrypt(raw[16:]), AES.block_size).decode("utf-8")
                    else:
                        cipher = AES.new(winning_key, AES.MODE_GCM, nonce=raw[:12])
                        plain  = cipher.decrypt_and_verify(raw[28:], raw[12:28]).decode("utf-8")
                    all_decrypted.append(plain)
                except Exception as e:
                    all_decrypted.append(None)
                    print(f"  Failed record on page {page}: {e}")

            print(f"Page {page} done. Total decrypted: {len(all_decrypted)}")

            if not body.get("has_more"):
                break
            page += 1

        # Save decrypted records
        with open("decrypted_records.json", "w") as f:
            json.dump(all_decrypted, f, indent=2)
        print(f"\nSaved to decrypted_records.json")
        print(f"Sample record 0: {all_decrypted[0]}")
        print(f"Sample record 1: {all_decrypted[1]}")
        print(f"Sample record 2: {all_decrypted[2]}")

        # Compute decrypted hash for Layer 2
        valid    = [d for d in all_decrypted if d]
        compact  = json.dumps(valid, separators=(',', ':')).encode('utf-8')
        dec_hash = hashlib.sha256(compact).hexdigest()
        print(f"\n{'='*60}")
        print(f"LAYER 2 ANSWER - decrypted_hash:")
        print(f"{dec_hash}")
        print(f"{'='*60}")
        print(f"\nSubmit this:")
        print(json.dumps({
            "type": "decrypted_hash",
            "value": dec_hash,
            "notes": f"SHA-256 of 500 decrypted records using AES-{winning_mode}, key derived via {winning_name}"
        }, indent=2))

else:
    print("\n✗ No key worked. Paste this output and we'll try next approach.")
    print("Also try running: python fast_scan.py to find the key endpoint.")
    candidates = []

    raw_api_key = API_KEY.encode()
    candidates.append(("api_key_raw", raw_api_key))
    candidates.append(("api_key_sha256", hashlib.sha256(raw_api_key).digest()))

    if API_KEY.startswith("sa_"):
        stripped = API_KEY[3:].encode()
        candidates.append(("api_key_without_sa_raw", stripped))
        candidates.append(("api_key_without_sa_sha256", hashlib.sha256(stripped).digest()))

    sample = base64.b64decode(records[0])

    for name, key in candidates:
        print("\nTrying", name, "length", len(key))

        # AES-GCM attempt: first 12 bytes nonce, last 16 bytes tag included automatically
        if len(key) in [16, 24, 32] and len(sample) > 28:
            try:
                aesgcm = AESGCM(key)
                nonce = sample[:12]
                ciphertext = sample[12:]
                plain = aesgcm.decrypt(nonce, ciphertext, None)
                print("AESGCM SUCCESS:", name, plain[:200])
            except Exception as e:
                print("AESGCM failed")

        # Fernet attempt
        try:
            fkey = base64.urlsafe_b64encode(key[:32])
            f = Fernet(fkey)
            plain = f.decrypt(records[0].encode())
            print("FERNET SUCCESS:", name, plain[:200])
        except Exception:
            print("Fernet failed")