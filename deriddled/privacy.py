"""Salted hashing of user IDs and IP addresses before any data leaves the machine for a hosted model."""
import hashlib
import os
from functools import lru_cache

from dotenv import load_dotenv

from deriddled.config import ROOT


@lru_cache(maxsize=1)
def _salt() -> str:
    load_dotenv(ROOT / ".env")
    salt = os.environ.get("IP_HASH_SALT", "")
    if not salt or salt == "change-me":
        raise RuntimeError("IP_HASH_SALT is not set in .env")
    return salt


def hash_id(value, prefix: str) -> str:
    return f"{prefix}-{hashlib.sha256(f'{_salt()}|{prefix}|{value}'.encode()).hexdigest()[:10]}"


def user(value) -> str:
    return hash_id(int(value), "U")


def ip(value) -> str:
    return hash_id(str(value), "IP")


def subnet(value) -> str:
    return hash_id(str(value), "NET")
