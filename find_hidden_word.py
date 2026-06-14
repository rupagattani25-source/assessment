import re
import json
from collections import Counter




def find_layer3_hidden_word():
    with open("decrypted_dataset.jsonl", "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    print("\nTotal decrypted lines:", len(lines))

    # 1. Print first few records
    print("\nSample decrypted records:")
    for line in lines[:5]:
        print(line[:500])

    # 2. Search obvious keywords
    keywords = [
        "answer", "hidden", "secret", "word", "algorithm",
        "layer", "puzzle", "flag", "result", "final"
    ]

    print("\nKeyword matches:")
    for idx, line in enumerate(lines):
        lower = line.lower()
        if any(k in lower for k in keywords):
            print(f"\nRecord {idx}:")
            print(line[:1000])

    # 3. Extract alphabetic-only tokens
    all_text = "\n".join(lines)
    words = re.findall(r"\b[A-Za-z]{3,30}\b", all_text)

    counts = Counter(words)

    print("\nRare alphabetic words:")
    for word, count in counts.items():
        if count == 1 and len(word) >= 5:
            print(word)

    # 4. Try JSON parsing and inspect keys
    print("\nParsed JSON inspection:")
    for idx, line in enumerate(lines):
        try:
            obj = json.loads(line)
            print(f"Record {idx} keys:", obj.keys())

            for k, v in obj.items():
                if isinstance(v, str) and v.isalpha():
                    print("Alphabetic field found:", idx, k, v)

        except Exception:
            pass