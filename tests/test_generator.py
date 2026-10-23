import math
import string
from collections import Counter

import pytest

from quantumvault.generator import (
    AMBIGUOUS,
    MIN_ENTROPY_BITS,
    SYMBOLS,
    PasswordOptions,
    PasswordPolicyError,
    generate,
    required_length,
)


def test_default_password_is_quantum_safe():
    result = generate()
    assert len(result.password) == 48
    assert result.entropy_bits >= MIN_ENTROPY_BITS
    assert result.post_quantum_bits >= 128


def test_every_selected_class_is_present():
    for _ in range(200):
        pw = generate(PasswordOptions(length=40)).password
        assert any(c in string.ascii_lowercase for c in pw)
        assert any(c in string.ascii_uppercase for c in pw)
        assert any(c in string.digits for c in pw)
        assert any(c in SYMBOLS for c in pw)


def test_only_selected_classes_are_used():
    pw = generate(PasswordOptions(length=64, symbols=False, uppercase=False)).password
    assert set(pw) <= set(string.ascii_lowercase + string.digits)


def test_exclude_ambiguous():
    for _ in range(50):
        pw = generate(PasswordOptions(length=64, exclude_ambiguous=True)).password
        assert not set(pw) & AMBIGUOUS


def test_rejects_below_entropy_floor():
    with pytest.raises(PasswordPolicyError, match="256"):
        generate(PasswordOptions(length=20))
    with pytest.raises(PasswordPolicyError):
        generate(PasswordOptions(length=60, lowercase=False, uppercase=False, symbols=False))


def test_digits_only_allowed_when_long_enough():
    length = required_length(10)
    result = generate(PasswordOptions(length=length, lowercase=False, uppercase=False, symbols=False))
    assert result.password.isdigit()
    assert result.entropy_bits >= MIN_ENTROPY_BITS


def test_rejects_invalid_options():
    with pytest.raises(PasswordPolicyError):
        generate(PasswordOptions(length=48, lowercase=False, uppercase=False, digits=False, symbols=False))
    with pytest.raises(PasswordPolicyError):
        generate(PasswordOptions(length=10_000))


def test_passwords_are_unique():
    seen = {generate().password for _ in range(500)}
    assert len(seen) == 500


def test_character_distribution_is_roughly_uniform():
    # Chi-squared sanity check that no character is heavily favoured.
    opts = PasswordOptions(length=512)
    counts = Counter()
    for _ in range(40):
        counts.update(generate(opts).password)
    alphabet = string.ascii_lowercase + string.ascii_uppercase + string.digits + SYMBOLS
    expected = sum(counts.values()) / len(alphabet)
    chi2 = sum((counts[c] - expected) ** 2 / expected for c in alphabet)
    # 93 degrees of freedom; the 99.99th percentile is about 150.
    assert chi2 < 160


def test_entropy_is_close_to_theoretical_maximum():
    result = generate(PasswordOptions(length=48))
    upper_bound = 48 * math.log2(94)
    assert upper_bound - 1 < result.entropy_bits <= upper_bound
