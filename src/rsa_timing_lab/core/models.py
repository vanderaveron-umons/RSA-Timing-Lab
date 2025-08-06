import math
from dataclasses import dataclass
from rsa_timing_lab.utils.math import is_prime


@dataclass(frozen=True, slots=True)
class RSAPublicKey:
    """
    Represents a RSA public key, containing only the public elements.

    Attributes:
        n (int): The RSA modulus (the product of the two secret primes).
        e (int): The public exponent (typically 65537).

    Raises:
        ValueError: If the key is malformed.
    """
    n: int
    e: int

    def __post_init__(self):
        # Basic constraints
        if self.n <= 0:
            raise ValueError("Modulus (n) must be positive")
        if self.e < 3:
            raise ValueError("Public exponent (e) must be equal or greater than 3.")

        # Parity constraints
        if self.n % 2 == 0:
            raise ValueError("Modulus (n) must be odd.")
        if self.e % 2 == 0:
            raise ValueError("Public exponent (e) must be odd.")

        # Relationship and security constraints
        if self.e >= self.n:
            raise ValueError("Public exponent (e) must be strictly less than modulus (n).")
        if is_prime(self.n):
            raise ValueError("Modulus (n) must not be a prime number.")

@dataclass(frozen=True, slots=True)
class RSAKey:
    """
    Represents an RSA key, with both private and public elements.

    Attributes:
        n (int): The RSA modulus. It is the product of the two secret primes,
                 same as in the corresponding public key.
        e (int): The public exponent (typically 65537, same as in the corresponding public key).
        d (int): The private exponent (multiplicative inverse of e mod φ(n)).
        p (int): First prime factor.
        q (int): Second prime factor.

    Raises:
        ValueError: If the key is malformed.
    """
    n: int
    e: int
    d: int
    p: int
    q: int

    def __post_init__(self):
        if self.n <= 0:
            raise ValueError("Modulus (n) must be positive.")
        if self.n % 2 == 0:
            raise ValueError("Modulus (n) must be odd.")

        if self.e < 3:
            raise ValueError("Public exponent (e) must be equal or greater than 3.")
        if self.e % 2 == 0:
            raise ValueError("Public exponent (e) must be odd.")

        if self.e >= self.n:
            raise ValueError("Public exponent (e) must be strictly less than modulus (n).")

        if self.p <= 1:
            raise ValueError("First prime factor (p) must be strictly greater than 1.")

        if self.q <= 1:
            raise ValueError("Second prime factor (q) must be strictly greater than 1.")

        if self.p == self.q:
            raise ValueError(
                "First prime factor (p) must be different than second prime factor (q)."
            )

        if self.p * self.q != self.n:
            raise ValueError("Modulus (n) is not equal to the product of prime factors (p,q).")

        if not is_prime(self.p):
            raise ValueError("First prime factor (p) is not prime.")

        if not is_prime(self.q):
            raise ValueError("Second prime factor (q) is not prime.")

        phi = (self.p - 1) * (self.q - 1)
        if math.gcd(phi, self.e) != 1:
            raise ValueError("φ(n) is not coprime to e.")

        if self.d != pow(self.e, -1, phi):
            raise ValueError(
                "Private exponent (d) D is not the multiplicative inverse of e mod φ(n)."
            )


    @property
    def public_key(self) -> RSAPublicKey:
        """Returns the public part of the key as an RSAPublicKey instance."""
        return RSAPublicKey(n=self.n, e=self.e)


@dataclass(frozen=True, slots=True)
class TimingData:
    """
    Represents a single timing measurement for an RSA encryption operation.

    Attributes:
        ciphertext (int): The ciphertext value that was processed.
        timing (float): The observed execution time for the operation, in seconds.

    Raises:
        ValueError: If timing or ciphertext values are negative.
    """
    ciphertext: int
    timing: float

    def __post_init__(self):
        if self.timing < 0:
            raise ValueError("Timing cannot be negative.")
        if self.ciphertext < 0:
            raise ValueError("Ciphertext cannot be negative.")


@dataclass(frozen=True, slots=True)
class AttackResult:
    """
    Represents the result of a completed timing attack against RSA.

    Attributes:
        recovered_key_bits (str): The recovered private key, as a string (e.g., "101101...").
        attack_time (float): The time taken to perform the attack, in seconds.
        samples_used (int): The number of timing samples used to perform the attack.

    Raises:
        ValueError: If numeric values are negative or key_bits is malformed.
    """
    recovered_key_bits: str
    attack_time: float
    samples_used: int

    def __post_init__(self):
        if self.attack_time < 0:
            raise ValueError("Attack time cannot be negative.")

        if self.samples_used < 0:
            raise ValueError("Samples used cannot be negative.")

        if not self.recovered_key_bits:
            raise ValueError("Recovered key bits string cannot be empty.")

        if not all(c in '01' for c in self.recovered_key_bits):
            raise ValueError("Recovered key bits must only contain '0' and '1'.")
