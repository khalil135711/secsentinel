"""Offline password policy auditor.

Estimates strength from length, character variety and common weak patterns.
Everything runs locally; passwords are never printed in clear text and are
never sent anywhere.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import List

COMMON_PASSWORDS = frozenset(
    """
    password password1 password123 passw0rd p@ssword p@ssw0rd 123456 1234567
    12345678 123456789 1234567890 qwerty qwerty123 qwertz abc123 letmein
    welcome welcome1 admin admin123 administrator root toor login master
    monkey dragon football baseball iloveyou sunshine princess trustno1
    starwars superman batman shadow michael secret changeme default guest
    summer winter hallo hallo123 passwort test test123 000000 111111
    """.split()
)

KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "qwertzuiop", "1234567890")
LEET_MAP = str.maketrans({"@": "a", "4": "a", "0": "o", "1": "i", "!": "i",
                          "3": "e", "$": "s", "5": "s", "7": "t"})
RATINGS = ("very weak", "weak", "fair", "good", "strong")
MAX_BITS = 100.0


@dataclass
class Result:
    length: int
    entropy_bits: float
    rating: str
    issues: List[str] = field(default_factory=list)


def _pool_size(password: str) -> int:
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    if re.search(r"[ -/:-@\[-`{-~]", password):
        pool += 33
    if re.search(r"[^\x20-\x7e]", password):
        pool += 64
    return pool


def _has_sequence(password: str, length: int = 4) -> bool:
    low = password.lower()
    for i in range(len(low) - length + 1):
        diffs = {ord(low[i + j + 1]) - ord(low[i + j]) for j in range(length - 1)}
        if diffs == {1} or diffs == {-1}:
            return True
    return False


def _has_keyboard_run(password: str, length: int = 4) -> bool:
    low = password.lower()
    for row in KEYBOARD_ROWS:
        for line in (row, row[::-1]):
            for i in range(len(line) - length + 1):
                if line[i : i + length] in low:
                    return True
    return False


def audit_password(password: str) -> Result:
    issues: List[str] = []
    length = len(password)

    if length == 0:
        return Result(0, 0.0, RATINGS[0], ["empty password"])

    normalized = password.lower().translate(LEET_MAP)
    plain = password.lower()
    if plain in COMMON_PASSWORDS or normalized in COMMON_PASSWORDS:
        return Result(
            length, 0.0, RATINGS[0], ["found in list of very common passwords"]
        )
    stripped = re.sub(r"[\d\W_]+$", "", normalized)
    if stripped and stripped in COMMON_PASSWORDS:
        issues.append("common password with trailing digits/symbols")

    bits = length * math.log2(max(_pool_size(password), 2))

    if re.search(r"(.)\1{2,}", password):
        issues.append("contains a character repeated 3+ times")
        bits -= 15
    if _has_sequence(password):
        issues.append("contains an ascending/descending sequence (e.g. abcd, 4321)")
        bits -= 15
    if _has_keyboard_run(password):
        issues.append("contains a keyboard pattern (e.g. qwer, asdf)")
        bits -= 15
    if "common password" in " ".join(issues):
        bits = min(bits, 25)
    if length < 12:
        issues.append("shorter than 12 characters")
    if not (re.search(r"[a-z]", password) and re.search(r"[A-Z]", password)):
        issues.append("no mix of upper- and lowercase letters")
    if not re.search(r"\d", password):
        issues.append("contains no digit")
    # Character-pool estimates badly overrate long word-based passphrases,
    # so the estimate is capped instead of claiming implausible precision.
    bits = min(max(bits, 0.0), MAX_BITS)

    if bits < 28:
        score = 0
    elif bits < 36:
        score = 1
    elif bits < 60:
        score = 2
    elif bits < 80:
        score = 3
    else:
        score = 4
    if length < 12:
        score = min(score, 2)

    return Result(length, round(bits, 1), RATINGS[score], issues)


def rating_rank(rating: str) -> int:
    return RATINGS.index(rating)


def mask(password: str) -> str:
    return "*" * min(len(password), 12)
