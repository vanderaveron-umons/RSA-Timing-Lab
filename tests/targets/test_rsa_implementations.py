import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from rsa_timing_lab.core import TimedRSAInterface, RSAKey
from rsa_timing_lab.utils.rsa_key_generator import RSAKeyGenerator
from rsa_timing_lab import targets  # Import the targets package to find implementations


# --- 1. Helper function to discover all implementations ---
def find_rsa_implementations():
    """Dynamically finds all classes that implement TimedRSAInterface."""
    implementations = []
    for name in dir(targets):
        obj = getattr(targets, name)
        if isinstance(obj, type) and issubclass(obj, TimedRSAInterface) and obj is not TimedRSAInterface:
            implementations.append(obj)
    if not implementations:
        pytest.fail("No RSA implementations found in the 'targets' package.")
    return implementations


# --- 2. Parametrize the entire test class with the discovered implementations ---
@pytest.mark.parametrize("rsa_class", find_rsa_implementations())
class TestAllRSAImplementations:
    """
    A comprehensive test suite that runs on ALL discovered implementations
    of TimedRSAInterface. It covers both functional conformance and
    interoperability with the 'cryptography' library.
    """

    @pytest.fixture
    def rsa_instance(self, rsa_class):
        """Creates an instance of the implementation currently being tested."""
        # Assumes the constructor takes no arguments, or only optional ones.
        return rsa_class()

    @pytest.fixture(scope="class")
    def our_key(self) -> RSAKey:
        """A single, shared key for all tests in this class."""
        return RSAKeyGenerator.generate_keypair(key_length=256, seed=123)

    # --- Conformance Tests (Internal Logic) ---

    def test_encrypt_decrypt_round_trip(self, rsa_instance, our_key):
        """Tests the internal encryption -> decryption cycle."""
        message = 12345
        ciphertext, _ = rsa_instance.timed_encrypt(message, our_key.public_key)
        decrypted_message, _ = rsa_instance.timed_decrypt(ciphertext, our_key)
        assert decrypted_message == message

    def test_sign_verify_round_trip(self, rsa_instance, our_key):
        """Tests the internal signing -> verification cycle."""
        message = 424242
        signature, _ = rsa_instance.timed_sign(message, our_key)
        is_valid, _ = rsa_instance.timed_verify(signature, message, our_key.public_key)
        assert is_valid is True

    # --- Interoperability Tests (with 'cryptography' library) ---

    @pytest.fixture(scope="class")
    def crypto_private_key(self, our_key):
        """Converts our key to a 'cryptography' library key object."""
        pub_nums = rsa.RSAPublicNumbers(e=our_key.e, n=our_key.n)
        priv_nums = rsa.RSAPrivateNumbers(
            p=our_key.p, q=our_key.q, d=our_key.d,
            dmp1=our_key.d % (our_key.p - 1),
            dmq1=our_key.d % (our_key.q - 1),
            iqmp=pow(our_key.q, -1, our_key.p),
            public_numbers=pub_nums
        )
        return priv_nums.private_key()

    def test_encrypt_here_decrypt_there(self, rsa_instance, our_key, crypto_private_key):
        """Encrypt with our code, decrypt with the reference library."""
        message = 54321
        ciphertext, _ = rsa_instance.timed_encrypt(message, our_key.public_key)

        # Decrypt using raw math, as 'cryptography' lib adds padding by default
        priv_nums = crypto_private_key.private_numbers()
        decrypted = pow(ciphertext, priv_nums.d, priv_nums.public_numbers.n)

        assert decrypted == message

    def test_decrypt_here_encrypt_there(self, rsa_instance, our_key, crypto_private_key):
        """Encrypt with the reference library, decrypt with our code."""
        message = 1337
        # Encrypt using raw math
        pub_nums = crypto_private_key.private_numbers().public_numbers
        ciphertext = pow(message, pub_nums.e, pub_nums.n)

        decrypted, _ = rsa_instance.timed_decrypt(ciphertext, our_key)

        assert decrypted == message