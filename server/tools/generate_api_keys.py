#!/usr/bin/env python3

import sys
import hashlib
import bcrypt
import getpass


def hash_api_key(api_key: str, rounds: int = 12) -> str:
    digest = hashlib.sha256(api_key.encode("utf-8")).digest()
    hashed = bcrypt.hashpw(digest, bcrypt.gensalt(rounds=rounds))
    return hashed.decode("utf-8")


def main() -> int:
    rounds = 12
    values = []

    for arg in sys.argv[1:]:
        if arg.startswith("--rounds="):
            rounds = int(arg.split("=", 1)[1])
        else:
            values.append(arg)

    if not values:
        print("API Key eingeben. Leer lassen und Enter drücken zum Beenden.", file=sys.stderr)
        while True:
            value = getpass.getpass("API Key: ")
            if not value:
                break
            values.append(value)

    if not values:
        print("Keine API Keys angegeben.", file=sys.stderr)
        return 1

    print("security:")
    print("  api_keys:")
    for value in values:
        print(f'    - "{hash_api_key(value, rounds)}"')

    return 0


if __name__ == "__main__":
    raise SystemExit(main())