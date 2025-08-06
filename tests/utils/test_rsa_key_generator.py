import pytest
from rsa_timing_lab.utils.rsa_key_generator import RSAKeyGenerator
from rsa_timing_lab.core import RSAKey


class TestRSAKeyGenerator:
    """
    Tests for the RSAKeyGenerator utility.
    """

    @pytest.mark.parametrize("key_length", [64, 128])
    def test_generate_keypair_properties(self, key_length):
        """
        Tests that the generated key has the correct bit length and is valid.

        The validity check is implicitly performed by the RSAKey dataclass's
        __post_init__ method. If it instantiates without error, the key is
        mathematically consistent.
        """
        try:
            key = RSAKeyGenerator.generate_keypair(key_length=key_length)

            # 1. Verify that the created object is of the correct type
            assert isinstance(key, RSAKey)

            # 2. Verify the modulus has the correct bit length
            assert key.n.bit_length() == key_length

        except (ValueError, RuntimeError) as e:
            pytest.fail(f"generate_keypair failed for {key_length}-bit key: {e}")

    def test_generate_keypair_is_deterministic_with_seed(self):
        """
        Tests that generate_keypair produces the same key for the same seed,
        and different keys for different seeds.
        """
        # Generate two keys with the same seed
        key1 = RSAKeyGenerator.generate_keypair(key_length=64, seed=42)
        key2 = RSAKeyGenerator.generate_keypair(key_length=64, seed=42)

        # Generate a third key with a different seed
        key3 = RSAKeyGenerator.generate_keypair(key_length=64, seed=43)

        # Keys generated with the same seed must be identical
        assert key1 == key2

        # Keys generated with different seeds must be different
        assert key1 != key3

    def test_generate_keypair_with_invalid_exponent_raises_error(self):
        """
        Tests that providing an invalid public exponent raises a ValueError.
        """
        with pytest.raises(ValueError, match="Public exponent must be odd"):
            RSAKeyGenerator.generate_keypair(key_length=64, public_exponent=65536)  # Even exponent