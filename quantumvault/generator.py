"""Cryptographically secure password generation.

Security model
--------------
The best known quantum attack against a randomly generated secret is Grover's
algorithm, which searches an unstructured space of size N in roughly sqrt(N)
steps. A password with ``b`` bits of entropy therefore keeps ``b / 2`` bits of
security against a quantum adversary.

To retain at least 128 bits of post-quantum security (the same level NIST
assigns to AES-256 against quantum attackers) every password produced here
must carry at least 256 bits of entropy. Requests below that floor are
rejected rather than silently weakened.

Randomness comes exclusively from the operating system CSPRNG via the
``secrets`` module. ``secrets.choice`` uses rejection sampling internally, so
every character is drawn uniformly with no modulo bias.
"""

from __future__ import annotations

import math
import secrets
import string
from dataclasses import dataclass

# Minimum entropy (bits) for any generated password. 256 bits of entropy
# leaves 128 bits of security after Grover's quadratic speedup.
MIN_ENTROPY_BITS = 256
MIN_LENGTH = 16
MAX_LENGTH = 512
DEFAULT_LENGTH = 48

LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
# Printable ASCII symbols only, so passwords work on every keyboard layout.
SYMBOLS = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
# Characters that are easy to confuse when reading a password aloud or on paper.
AMBIGUOUS = set("Il1O0o|`'\"")


class PasswordPolicyError(ValueError):
    """Raised when requested options cannot meet the security floor."""


@dataclass(frozen=True)
class PasswordOptions:
    length: int = DEFAULT_LENGTH
    lowercase: bool = True
    uppercase: bool = True
    digits: bool = True
    symbols: bool = True
    exclude_ambiguous: bool = False

    def character_classes(self) -> list[str]:
        classes = []
        if self.lowercase:
            classes.append(LOWERCASE)
        if self.uppercase:
            classes.append(UPPERCASE)
        if self.digits:
            classes.append(DIGITS)
        if self.symbols:
            classes.append(SYMBOLS)
        if self.exclude_ambiguous:
            classes = ["".join(c for c in cls if c not in AMBIGUOUS) for cls in classes]
        return [cls for cls in classes if cls]


@dataclass(frozen=True)
class GeneratedPassword:
    password: str
    entropy_bits: float
    post_quantum_bits: float
    alphabet_size: int


def alphabet_for(options: PasswordOptions) -> str:
    return "".join(options.character_classes())


def entropy_bits(length: int, alphabet_size: int) -> float:
    """Shannon entropy of a uniformly random string of the given shape."""
    if alphabet_size < 2 or length < 1:
        return 0.0
    return length * math.log2(alphabet_size)


def required_length(alphabet_size: int, target_bits: float = MIN_ENTROPY_BITS) -> int:
    """Smallest length that reaches ``target_bits`` with the given alphabet."""
    return max(MIN_LENGTH, math.ceil(target_bits / math.log2(alphabet_size)))


def validate(options: PasswordOptions) -> str:
    """Check options against the policy and return the alphabet to use."""
    if not isinstance(options.length, int) or isinstance(options.length, bool):
        raise PasswordPolicyError("Length must be an integer.")
    if not MIN_LENGTH <= options.length <= MAX_LENGTH:
        raise PasswordPolicyError(f"Length must be between {MIN_LENGTH} and {MAX_LENGTH}.")

    classes = options.character_classes()
    if not classes:
        raise PasswordPolicyError("Select at least one character set.")
    if options.length < len(classes):
        raise PasswordPolicyError("Length is shorter than the number of character sets.")

    alphabet = "".join(classes)
    bits = _exact_entropy(options.length, classes)
    if bits < MIN_ENTROPY_BITS:
        needed = required_length(len(alphabet))
        raise PasswordPolicyError(
            f"These settings give only {bits:.0f} bits of entropy. Quantum resistance "
            f"requires at least {MIN_ENTROPY_BITS} bits; use a length of {needed} or "
            f"more, or enable more character sets."
        )
    return alphabet


def generate(options: PasswordOptions | None = None) -> GeneratedPassword:
    """Generate a uniformly random password that satisfies ``options``.

    Every selected character class is guaranteed to appear. This is done by
    rejection sampling whole passwords (draw, check, redraw), which keeps the
    result uniformly distributed over all valid passwords instead of biasing
    particular positions the way "insert one of each class" approaches do.
    """
    options = options or PasswordOptions()
    alphabet = validate(options)
    classes = options.character_classes()

    while True:
        candidate = "".join(secrets.choice(alphabet) for _ in range(options.length))
        if all(any(ch in cls for ch in candidate) for cls in classes):
            break

    # Report the exact entropy of the set of valid passwords, which is
    # marginally below length * log2(alphabet) because of the class rule.
    bits = _exact_entropy(options.length, classes)
    return GeneratedPassword(
        password=candidate,
        entropy_bits=bits,
        post_quantum_bits=bits / 2,
        alphabet_size=len(alphabet),
    )


def _exact_entropy(length: int, classes: list[str]) -> float:
    """log2 of the number of strings that contain every class at least once."""
    sizes = [len(c) for c in classes]
    total = sum(sizes)
    n = len(sizes)
    count = 0
    # Inclusion-exclusion over subsets of classes that are missing.
    for mask in range(1 << n):
        missing = sum(sizes[i] for i in range(n) if mask >> i & 1)
        sign = -1 if bin(mask).count("1") % 2 else 1
        count += sign * (total - missing) ** length
    return math.log2(count)
