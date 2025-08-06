import time
from typing import Tuple, Optional


from rsa_timing_lab.core import TimedRSAInterface, RSAPublicKey, RSAKey

class VulnerableRSA(TimedRSAInterface):
    """
    A vulnerable RSA implementation using Montgomery arithmetic.
    An optional delay can be introduced to amplify the timing side-channel.
    """

    def __init__(self, sleep_duration: Optional[float] = None):
        self.sleep_duration = sleep_duration

    def _perform_timed_exponentiation(self, base: int, exp: int, mod: int) -> Tuple[int, float]:
        """
        Private worker method to handle timing and modular exponentiation.
        """
        if base >= mod or base < 0:
            raise ValueError("Base must be non-negative and smaller than the modulus.")

        start_time = time.perf_counter()
        result = _exponent(base, exp, mod, self.sleep_duration)
        timing = time.perf_counter() - start_time
        return result, timing

    def timed_encrypt(self, message: int, public_key: RSAPublicKey) -> Tuple[int, float]:
        return self._perform_timed_exponentiation(
            base=message,
            exp=public_key.e,
            mod=public_key.n
        )

    def timed_decrypt(self, ciphertext: int, private_key: RSAKey) -> Tuple[int, float]:
        return self._perform_timed_exponentiation(
            base=ciphertext,
            exp=private_key.d,
            mod=private_key.n
        )

def _exponent(base: int, exp: int, modulus: int, sleep_duration: Optional[float] = None) -> int:
    """
    Private helper function for modular exponentiation using Montgomery arithmetic.

    Args:
        base (int): Base number
        exp (int): Exponent
        modulus (int): Modulus (must be odd)
        sleep_duration (float, optional): Sleep time for side-channel timing leakage amplification

    Returns:
        int: base^exp mod modulus

    """
    # Initialize Montgomery context
    ctx = _MontgomeryContext(modulus, sleep_duration)

    # Convert base to Montgomery form
    base_mont = ctx.to_mont(base)

    # Initialize result to 1 in Montgomery form
    result_mont = ctx.one_mont

    # Multiply-then-square from MSB to LSB
    for i in range(exp.bit_length() - 1, -1, -1):
        # Conditional multiplication (if current bit is 1)
        if (exp >> i) & 1:
            result_mont = ctx.multiply(result_mont, base_mont)

        # Squaring (always, except for the last iteration)
        if i > 0:
            result_mont = ctx.multiply(result_mont, result_mont)

    return ctx.from_mont(result_mont)

class _MontgomeryContext:
    """
    Private helper class for modular multiplication using Montgomery arithmetic.

    Montgomery arithmetic represents numbers in a special form that allows
    efficient modular multiplication without expensive division operations.

    Includes a configurable delay in the extra reduction step in the Montgomery multiplication
    in order to increase the timing effect for a side-channel attack demonstration.

    Args:
        modulus (int): The modulus (Montgomery multiplication requires odd modulus).
        sleep_duration (float, optional): Time to sleep on extra reduction.
                                          Used for side-channel attack demo.

    Raises:
        ValueError: If modulus is even.
    """

    def __init__(self, modulus: int, sleep_duration: Optional[float] = None):
        if modulus % 2 == 0:
            raise ValueError("Montgomery arithmetic requires an odd modulus.")

        self.modulus = modulus
        self.sleep_duration = sleep_duration

        # Montgomery parameters
        self.k = modulus.bit_length()  # Number of bits in modulus
        self.R = 1 << self.k           # R = 2^k (Montgomery radix)

        # Compute n' such that n * n' ≡ -1 (mod R)
        # We use: n' = R - n^(-1) mod R
        self.n_prime = self.R - pow(self.modulus, -1, self.R)

        # Montgomery representation of 1 (used as initial value)
        self.one_mont = self.R % self.modulus

    def _reduce(self, t: int) -> int:
        """
           Montgomery reduction: convert from extended form back to Montgomery form.

           Given t in extended Montgomery form, compute t/R mod n efficiently
           without division by using the Montgomery algorithm.

           Args:
               t (int): Number in extended Montgomery form

           Returns:
               int: Reduced result (t/R mod n) in Montgomery form
       """
        # Compute m = (t mod R) * n' mod R
        m = ((t & (self.R - 1)) * self.n_prime) & (self.R - 1)

        # Compute u = (t + m*n) / R
        u = (t + m * self.modulus) >> self.k

        # Check if extra reduction is needed
        if u >= self.modulus:
            if self.sleep_duration is not None:
                time.sleep(self.sleep_duration)
            u = u - self.modulus
        return u

    def to_mont(self, x: int) -> int:
        """
           Convert a regular integer to Montgomery form.

           Args:
               x (int): Regular integer

           Returns:
               int: x in Montgomery form (x * R mod n)
       """
        return self._reduce(x * (self.R * self.R % self.modulus))

    def from_mont(self, x_mont: int) -> int:
        """
            Convert from Montgomery form back to regular integer.

            Args:
                x_mont (int): Integer in Montgomery form

            Returns:
                int: Regular integer (x_mont / R mod n)
        """
        return self._reduce(x_mont)

    def multiply(self, a_mont: int, b_mont: int) -> int:
        """
            Multiply two numbers in Montgomery form.

            The result is also in Montgomery form.

            Args:
                a_mont (int): First operand in Montgomery form.
                b_mont (int): Second operand in Montgomery form.

            Returns:
                int: Product in Montgomery form
        """
        return self._reduce(a_mont * b_mont)
