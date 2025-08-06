import pytest
from rsa_timing_lab.utils.math import is_prime, generate_rsa_prime


class TestMathUtils:
    """
    Tests for the mathematical utility functions.
    """

    # --- Tests for is_prime ---

    @pytest.mark.parametrize("prime_number", [
        2, 3, 5, 7, 11, 13, 17, 19, 8191  # 8191 is a Mersenne prime
    ])
    def test_is_prime_with_known_primes(self, prime_number):
        """Tests that is_prime correctly identifies known prime numbers."""
        assert is_prime(prime_number) is True

    @pytest.mark.parametrize("composite_number", [
        -1, 0, 1, 4, 6, 8, 9, 10, 12, 15, 21, 100
    ])
    def test_is_prime_with_composite_numbers(self, composite_number):
        """Tests that is_prime correctly identifies non-prime numbers."""
        assert is_prime(composite_number) is False

    # --- Tests for generate_rsa_prime ---

    @pytest.mark.parametrize("bits", [16, 32, 64])
    def test_generate_rsa_prime_properties(self, bits):
        """
        Tests that the generated prime has the correct properties:
        1. It has the exact specified bit length.
        2. It is indeed a prime number.
        3. It is an odd number.
        """
        generated_prime = generate_rsa_prime(bits)

        # 1. Check bit length
        assert generated_prime.bit_length() == bits

        # 2. Check for primality
        assert is_prime(generated_prime) is True

        # 3. Check for oddness (necessary for RSA primes > 2)
        assert generated_prime % 2 == 1

    def test_generate_rsa_prime_uniqueness(self):
        """
        Tests that subsequent calls generate different primes.
        This is a basic sanity check for the randomness.
        """
        prime1 = generate_rsa_prime(16)
        prime2 = generate_rsa_prime(16)
        assert prime1 != prime2