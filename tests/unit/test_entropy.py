"""Tests for Shannon entropy analysis."""

from __future__ import annotations

from skillsecurity.privacy.entropy import (
    extract_high_entropy_tokens,
    is_likely_secret,
    shannon_entropy,
)


class TestShannonEntropy:
    def test_empty_string(self) -> None:
        assert shannon_entropy("") == 0.0

    def test_single_char(self) -> None:
        assert shannon_entropy("aaaa") == 0.0

    def test_two_chars_equal_freq(self) -> None:
        assert abs(shannon_entropy("ab") - 1.0) < 0.01

    def test_english_text_moderate_entropy(self) -> None:
        text = "the quick brown fox jumps over the lazy dog"
        e = shannon_entropy(text)
        assert 3.0 < e < 4.5

    def test_random_key_high_entropy(self) -> None:
        key = "aB3xQ9mKpL7wR2nT5vJ8hY4gF6cE1dU"
        e = shannon_entropy(key)
        assert e > 4.0


class TestIsLikelySecret:
    def test_short_string_not_secret(self) -> None:
        assert not is_likely_secret("abc123")

    def test_english_word_not_secret(self) -> None:
        assert not is_likely_secret("this_is_a_normal_variable_name_here")

    def test_random_key_is_secret(self) -> None:
        assert is_likely_secret("aB3xQ9mKpL7wR2nT5vJ8hY4gF6cE1dUzX")

    def test_uuid_excluded(self) -> None:
        assert not is_likely_secret("550e8400-e29b-41d4-a716-446655440000")

    def test_hex_hash_excluded(self) -> None:
        assert not is_likely_secret("a" * 64)

    def test_file_path_excluded(self) -> None:
        assert not is_likely_secret("/usr/local/bin/some_long_path_here")

    def test_url_excluded(self) -> None:
        assert not is_likely_secret("https://example.com/very/long/path/here")


class TestExtractHighEntropyTokens:
    def test_no_tokens_in_normal_text(self) -> None:
        text = "Hello world, this is a normal sentence."
        assert extract_high_entropy_tokens(text) == []

    def test_finds_embedded_key(self) -> None:
        text = "my token is aB3xQ9mKpL7wR2nT5vJ8hY4gF6cE1dUzX please use it"
        tokens = extract_high_entropy_tokens(text)
        assert len(tokens) >= 1
        assert "aB3xQ9mKpL7wR2nT5vJ8hY4gF6cE1dUzX" in tokens
