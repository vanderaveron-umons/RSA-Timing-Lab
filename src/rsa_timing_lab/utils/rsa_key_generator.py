import math
import random
from typing import Optional

from rsa_timing_lab.core import RSAKey
from rsa_timing_lab.utils.math import generate_rsa_prime

class RSAKeyGenerator:
    """
    Utility class to generate RSA key pairs.
    """

    @staticmethod
    def generate_keypair(key_length: int, public_exponent: int = 65537, max_attempts: int = 10000, seed: Optional[int] = None) -> RSAKey:
        """
        Generate a new RSA key pair with the specified bit length.

        Args:
            key_length (int): Desired bit length of the RSA modulus (e.g., 2048).
            public_exponent (int): The public exponent (e). Defaults to 65537.
            max_attempts (int): The maximum number of attempts to generate RSA keys. Defaults to 10000.
            seed (int, optional): random seed for forcing reproducibility.

        Returns:
            RSAKey: The RSAKey object containing all key components (public and private).

        Raises:
            ValueError: If public_exponent is invalid.
            RuntimeError: If unable to generate suitable primes after max_attempts.
        """
        if public_exponent < 3 or public_exponent % 2 == 0:
            raise ValueError("Public exponent must be odd and equal or greater than 3.")

        if seed is not None:
            random.seed(seed)

        e = public_exponent
        prime_length = key_length // 2

        # Loop until the generated key pair respect the proper constraints or the
        # max attempts limit is reached
        for _ in range(max_attempts):
            # Generate two prime numbers of equal bit length
            p = generate_rsa_prime(prime_length)
            q = generate_rsa_prime(prime_length)

            # Ensure primes are distinct
            if p == q:
                continue

            # Compute RSA parameters
            n = p * q
            phi = (p - 1) * (q - 1)

            # Verify constraints:
            # 1. Modulus has exactly the desired bit length
            # 2. e and φ(n) are coprime (required for d to exist)
            if n.bit_length() == key_length and math.gcd(phi, e) == 1:
                # Compute private exponent d = e^(-1) mod φ(n)
                d = pow(public_exponent, -1, phi)
                return RSAKey(n, e, d, p, q)

        raise RuntimeError(f"Unable to generate suitable RSA key pair after {max_attempts} attempts")
