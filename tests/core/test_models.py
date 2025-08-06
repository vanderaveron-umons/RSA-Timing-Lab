"""
Tests for RSA-Timing-Lab core models.
Place this file in: tests/core/test_models.py

Note: The order of validations in models.py matters!
Tests are designed to trigger specific errors while avoiding
earlier validations in the chain.

Coverage notes:
- Some validation checks (p<=1, q<=1, p==q) come after phi/d calculations
- When these values are invalid, earlier checks fail first
- This is good defensive programming - multiple layers of validation
"""

import pytest
from rsa_timing_lab.core.models import RSAKey, RSAPublicKey, TimingData, AttackResult


class TestRSAPublicKey:
    """Tests for RSAPublicKey validation."""

    def test_valid_key_creation(self):
        """Test that a valid RSAPublicKey can be created."""
        key = RSAPublicKey(n=143, e=7)
        assert key.n == 143
        assert key.e == 7

    def test_typical_fermat_exponent(self):
        """Test with common Fermat number F4 (65537) as exponent."""
        # For real RSA, the modulus would be much larger
        # Using a composite number large enough for e=65537
        # 65537 * 65539 = 4295098843 (product of two primes)
        large_n = 65537 * 65539  # Clearly composite and large enough
        key = RSAPublicKey(n=large_n, e=65537)
        assert key.e == 65537

    def test_negative_modulus_raises_error(self):
        """Test that negative modulus raises ValueError."""
        with pytest.raises(ValueError, match="[Mm]odulus.*positive"):
            RSAPublicKey(n=-143, e=7)

    def test_even_modulus_raises_error(self):
        """Test that even modulus raises ValueError (RSA uses p*q, so odd)."""
        with pytest.raises(ValueError, match="[Mm]odulus.*odd"):
            RSAPublicKey(n=142, e=7)

    def test_small_exponent_raises_error(self):
        """Test that exponent < 3 raises ValueError (security requirement)."""
        with pytest.raises(ValueError, match="[Ee]xponent.*greater than 3"):
            RSAPublicKey(n=143, e=1)
        with pytest.raises(ValueError, match="[Ee]xponent.*greater than 3"):
            RSAPublicKey(n=143, e=2)

    def test_even_exponent_raises_error(self):
        """Test that even exponent raises ValueError."""
        with pytest.raises(ValueError, match="[Ee]xponent.*odd"):
            RSAPublicKey(n=143, e=4)

    def test_prime_modulus_raises_error(self):
        """Test that prime modulus raises ValueError (must be composite)."""
        with pytest.raises(ValueError, match="[Mm]odulus.*not.*prime"):
            RSAPublicKey(n=11, e=7)  # 11 is prime

    def test_exponent_larger_than_modulus(self):
        """Test that e >= n raises ValueError."""
        with pytest.raises(ValueError, match="[Ee]xponent.*less than.*modulus"):
            RSAPublicKey(n=7, e=11)


class TestRSAKey:
    """Tests for full RSAKey validation."""

    # Valid test key: p=11, q=13, n=143, e=7, d=103
    VALID_KEY = {
        'n': 143,
        'e': 7,
        'd': 103,
        'p': 11,
        'q': 13
    }

    def test_valid_key_creation(self):
        """Test that a valid RSAKey can be created."""
        key = RSAKey(**self.VALID_KEY)
        assert key.n == 143
        assert key.e == 7
        assert key.d == 103
        assert key.p == 11
        assert key.q == 13

    def test_public_key_extraction(self):
        """Test that public_key property returns correct RSAPublicKey."""
        key = RSAKey(**self.VALID_KEY)
        pub = key.public_key
        assert isinstance(pub, RSAPublicKey)
        assert pub.n == key.n
        assert pub.e == key.e

    def test_wrong_modulus_raises_error(self):
        """Test that n != p*q raises ValueError."""
        params = self.VALID_KEY.copy()
        params['n'] = 145  # Wrong value but odd to avoid parity error
        with pytest.raises(ValueError, match="[Mm]odulus.*equal.*product"):
            RSAKey(**params)

    def test_non_prime_p_raises_error(self):
        """Test that non-prime p raises ValueError."""
        params = self.VALID_KEY.copy()
        params['p'] = 9  # 9 = 3*3, not prime but odd
        params['n'] = 9 * params['q']  # 9 * 13 = 117 (odd)
        # Calculate correct d to avoid d error
        phi = (9 - 1) * (params['q'] - 1)  # 8 * 12 = 96
        params['d'] = pow(params['e'], -1, phi)  # Calculate correct d
        with pytest.raises(ValueError, match="[Ff]irst prime.*prime"):
            RSAKey(**params)

    def test_non_prime_q_raises_error(self):
        """Test that non-prime q raises ValueError."""
        params = self.VALID_KEY.copy()
        params['q'] = 9  # 9 = 3*3, not prime
        params['n'] = params['p'] * 9  # 11 * 9 = 99 (odd)
        # Calculate correct d
        phi = (params['p'] - 1) * (9 - 1)  # 10 * 8 = 80
        # Verify gcd(e, phi) = 1: gcd(7, 80) = 1 ✓
        params['d'] = pow(params['e'], -1, phi)
        with pytest.raises(ValueError, match="[Ss]econd prime.*prime"):
            RSAKey(**params)

    def test_equal_primes_raises_error(self):
        """Test that p == q raises ValueError (vulnerable to Fermat factorization)."""
        params = self.VALID_KEY.copy()
        params['q'] = params['p']  # p = q = 11
        params['n'] = params['p'] ** 2  # 121
        # Calculate correct d to avoid d error
        phi = (params['p'] - 1) * (params['p'] - 1)  # 10 * 10 = 100
        # e=7, phi=100, gcd(7,100)=1 ✓
        params['d'] = pow(params['e'], -1, phi)  # 7^-1 mod 100 = 43
        with pytest.raises(ValueError, match="prime factor.*different"):
            RSAKey(**params)

    def test_wrong_private_exponent_raises_error(self):
        """Test that incorrect d raises ValueError."""
        params = self.VALID_KEY.copy()
        params['d'] = 104  # Wrong value
        with pytest.raises(ValueError, match="[Pp]rivate exponent.*inverse"):
            RSAKey(**params)

    def test_gcd_not_one_raises_error(self):
        """Test that gcd(e, φ(n)) != 1 raises ValueError."""
        # p=5, q=7, n=35, φ(n)=24, e=9 (gcd(9,24)=3≠1)
        with pytest.raises(ValueError, match="coprime"):
            RSAKey(n=35, e=9, d=1, p=5, q=7)

    def test_small_first_prime_factor_raises_error(self):
        """Test that p <= 1 raises ValueError."""
        params = self.VALID_KEY.copy()
        params['p'] = 1  # Wrong value
        with pytest.raises(ValueError, match="[Ff]irst prime factor.*greater than 1"):
            RSAKey(**params)

        params['p'] = 0  # Wrong value
        with pytest.raises(ValueError, match="[Ff]irst prime factor.*greater than 1"):
            RSAKey(**params)

        params['p'] = -1  # Wrong value
        with pytest.raises(ValueError, match="[Ff]irst prime factor.*greater than 1"):
            RSAKey(**params)

    def test_small_second_prime_factor_raises_error(self):
        """Test that q <= 1 raises ValueError."""
        params = self.VALID_KEY.copy()
        params['q'] = 1  # Wrong value
        with pytest.raises(ValueError, match="[Ss]econd prime factor.*greater than 1"):
            RSAKey(**params)

        params['q'] = 0  # Wrong value
        with pytest.raises(ValueError, match="[Ss]econd prime factor.*greater than 1"):
            RSAKey(**params)

        params['q'] = -1  # Wrong value
        with pytest.raises(ValueError, match="[Ss]econd prime factor.*greater than 1"):
            RSAKey(**params)


    # --- Additional tests for better coverage ---
    def test_negative_modulus_in_full_key(self):
        """Test that n <= 0 is rejected in RSAKey."""
        with pytest.raises(ValueError, match="[Mm]odulus.*positive"):
            RSAKey(n=-143, e=7, d=103, p=11, q=13)

    def test_even_modulus_in_full_key(self):
        """Test that even n is rejected in RSAKey."""
        with pytest.raises(ValueError, match="[Mm]odulus.*odd"):
            RSAKey(n=144, e=7, d=103, p=12, q=12)

    def test_small_public_exponent_in_full_key(self):
        """Test that e < 3 is rejected in RSAKey."""
        with pytest.raises(ValueError, match="[Ee]xponent.*greater than 3"):
            RSAKey(n=143, e=2, d=103, p=11, q=13)

    def test_even_public_exponent_in_full_key(self):
        """Test that even e is rejected in RSAKey."""
        with pytest.raises(ValueError, match="[Ee]xponent.*odd"):
            RSAKey(n=143, e=4, d=103, p=11, q=13)

    def test_exponent_too_large_in_full_key(self):
        """Test that e >= n is rejected in RSAKey."""
        # Use odd exponent larger than n to avoid "even exponent" error
        with pytest.raises(ValueError, match="[Ee]xponent.*less than.*modulus"):
            RSAKey(n=143, e=151, d=103, p=11, q=13)  # 151 is odd and > 143


class TestTimingData:
    """Tests for TimingData validation."""

    def test_valid_timing_creation(self):
        """Test valid TimingData creation."""
        data = TimingData(ciphertext=12345, timing=0.001)
        assert data.ciphertext == 12345
        assert data.timing == 0.001

    def test_zero_timing_allowed(self):
        """Test that zero timing is allowed (edge case)."""
        data = TimingData(ciphertext=0, timing=0.0)
        assert data.timing == 0.0

    def test_negative_timing_raises_error(self):
        """Test that negative timing raises ValueError."""
        with pytest.raises(ValueError, match="[Tt]iming.*negative"):
            TimingData(ciphertext=123, timing=-0.001)

    def test_negative_ciphertext_raises_error(self):
        """Test that negative ciphertext raises ValueError."""
        with pytest.raises(ValueError, match="[Cc]iphertext.*negative"):
            TimingData(ciphertext=-1, timing=0.001)

    def test_large_ciphertext_values(self):
        """Test with large realistic ciphertext values."""
        large_ct = 2 ** 512 - 1  # Typical for RSA-512
        data = TimingData(ciphertext=large_ct, timing=0.123)
        assert data.ciphertext == large_ct


class TestAttackResult:
    """Tests for AttackResult validation."""

    def test_valid_result_creation(self):
        """Test valid AttackResult creation."""
        result = AttackResult(
            recovered_key_bits="101101",
            attack_time=10.5,
            samples_used=1000
        )
        assert result.recovered_key_bits == "101101"
        assert result.attack_time == 10.5
        assert result.samples_used == 1000

    def test_empty_key_bits_raises_error(self):
        """Test that empty key bits string raises ValueError."""
        with pytest.raises(ValueError, match="[Kk]ey bits.*empty"):
            AttackResult(
                recovered_key_bits="",
                attack_time=10.5,
                samples_used=1000
            )

    def test_invalid_key_bits_raises_error(self):
        """Test that non-binary characters in key bits raise ValueError."""
        with pytest.raises(ValueError, match="[Kk]ey bits.*0.*1"):
            AttackResult(
                recovered_key_bits="10120",  # Contains '2'
                attack_time=10.5,
                samples_used=1000
            )

    def test_negative_attack_time_raises_error(self):
        """Test that negative attack time raises ValueError."""
        with pytest.raises(ValueError, match="[Aa]ttack time.*negative"):
            AttackResult(
                recovered_key_bits="101",
                attack_time=-1.0,
                samples_used=1000
            )

    def test_negative_samples_raises_error(self):
        """Test that negative samples count raises ValueError."""
        with pytest.raises(ValueError, match="[Ss]amples.*negative"):
            AttackResult(
                recovered_key_bits="101",
                attack_time=10.5,
                samples_used=-1
            )

    @pytest.mark.parametrize("invalid_bits", [
        "abc",  # Letters
        "10 11",  # Space
        "1.0",  # Decimal point
        "0b101",  # Binary prefix
        "0x101",  # Hex prefix
    ])
    def test_various_invalid_key_bits(self, invalid_bits):
        """Parametrized test for various invalid key bit strings."""
        with pytest.raises(ValueError):
            AttackResult(
                recovered_key_bits=invalid_bits,
                attack_time=1.0,
                samples_used=100
            )
