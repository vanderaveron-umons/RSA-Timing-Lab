import time
import random
import numpy as np
from typing import List, Optional

from rsa_timing_lab.core import TimingAttackInterface, RSAPublicKey, TimingData, AttackResult


class DhemAttack(TimingAttackInterface):
    """
    Implementation of the Dhem et al. timing attack against RSA published in
    "A Practical Implementation of the Timing Attack" (2000). DOI: 10.1007/10721064_15

    This attack exploits timing differences in Montgomery arithmetic to recover
    the private key bit by bit.
    It implements the TimingAttackInterface interface.
    """

    class _Oracle:
        """
        Predicts whether a Montgomery multiplication will require an extra reduction step,
        which corresponds to predicting a "slow" operation in RSA.
        """

        def __init__(self, modulus: int):
            self.modulus = modulus
            self.k = modulus.bit_length()
            self.R = 1 << self.k
            self.n_prime = self.R - pow(self.modulus, -1, self.R)

        def predict_reduction_needed(self, a: int, b: int) -> bool:
            """
              Predicts if montgomery_multiply(a, b) will need a final subtraction by
              simulating the internal steps of the algorithm.
              """
            t = a * b
            m = ((t & (self.R - 1)) * self.n_prime) & (self.R - 1)
            u = (t + m * self.modulus) >> self.k
            return u >= self.modulus

    class _MontgomerySimulator:
        """
        Simulates Montgomery arithmetic to compute intermediate states of the RSA decryption.
        This is the attacker's internal tool to model the target's behavior.
        """

        def __init__(self, modulus: int):
            self.modulus = modulus
            self.k = modulus.bit_length()
            self.R = 1 << self.k
            self.n_prime = self.R - pow(self.modulus, -1, self.R)
            self.one_mont = self.R % self.modulus

        def to_montgomery(self, x: int) -> int:
            return (x * self.R) % self.modulus

        def montgomery_reduce(self, t: int) -> int:
            m = ((t & (self.R - 1)) * self.n_prime) & (self.R - 1)
            u = (t + m * self.modulus) >> self.k
            return u - self.modulus if u >= self.modulus else u

        def montgomery_multiply(self, a_mont: int, b_mont: int) -> int:
            return self.montgomery_reduce(a_mont * b_mont)

    def __init__(self, public_key: RSAPublicKey, timing_data: List[TimingData], verbose: bool = False):
        self.public_key = public_key
        self.timing_data = timing_data
        self.verbose = verbose

        # Initialize internal helpers
        self.oracle = self._Oracle(self.public_key.n)
        self.montgomery = self._MontgomerySimulator(self.public_key.n)

    @classmethod
    def from_data(cls, public_key: RSAPublicKey, timing_data: List[TimingData], **kwargs) -> 'DhemAttack':
        """
        Factory method to create a configured attack instance.

        Args:
            public_key (RSAPublicKey): RSA public key (provides modulus, and allows to check if the recovered private key works.
            timing_data (List[TimingData]): List of timing measurements with ciphertexts.
            kwargs: Additional attack-specific parameters.

        Returns:
            DhemAttack: A configured instance of the class.
        """
        return cls(public_key, timing_data, **kwargs)

    def attack(self, limit_max_samples: Optional[int] = None) -> AttackResult:
        """
          Execute the Dhem timing attack to recover the private key bit by bit.

          Args:
              limit_max_samples (int, optional): The maximum number of timing samples to use. Defaults to None, which uses all samples.

          Returns:
              AttackResult with recovered private key and timing information
          """
        start_time: float = time.time()

        samples_to_use: List[TimingData] = self.timing_data[
                                           :limit_max_samples] if limit_max_samples else self.timing_data
        candidate_key: str = self._attack(samples_to_use)

        # TODO: trim extra bits

        recovered_bits: str = self._trim_key(candidate_key, self.public_key)

        attack_time: float = time.time() - start_time
        return AttackResult(
            recovered_key_bits=recovered_bits,
            attack_time=attack_time,
            samples_used=len(samples_to_use)
        )

    def _attack(self, samples: List[TimingData]) -> str:
        """
          Private method to performs the Dhem timing attack.

          Args:
              samples (List[TimingData]): List of timing measurements with ciphertexts.

          Returns:
              str: The recovered bits.
          """

        recovered_bits = "1"  # MSB is always 1
        max_bits = self.public_key.n.bit_length()

        if self.verbose:
            print(f"Starting Dhem attack with {len(samples)} samples...")
            print(f"   Attacking bit 0/{max_bits - 1}...")
            print("     -> First bit is always 1")
            print("      -> Decision: bit 0 = 1")

        # Recover bits one by one (skip MSB and LSB)
        for bit_position in range(1, max_bits - 1):
            if self.verbose:
                print(f"   Attacking bit {bit_position}...")

            guessed_bit = self._find_next_bit(recovered_bits, samples)
            recovered_bits += guessed_bit

        # The LSB is always 1 as the private key must be odd
        if len(recovered_bits) < max_bits:
            recovered_bits += "1"

        if self.verbose:
            print(f"   Attacking bit {max_bits - 1}/{max_bits - 1}...")
            print("     -> Last bit is always 1")
            print(f"      -> Decision: bit {max_bits - 1} = 1")

        return recovered_bits

    def _find_next_bit(self, known_bits: str, timing_data: List[TimingData]) -> str:
        """
        Finds the next unknown bit by iterating through all samples, fully processing
        each one individually to partition them based on two oracle hypotheses.

        Args:
            known_bits (str): The known bits so far.
            timing_data (List[TimingData]): The timing measurements with ciphertexts.

        Returns:
            str: The guessed next bit.
        """
        M1: list[float] = []
        M2: list[float] = []
        M3: list[float] = []
        M4: list[float] = []

        # Main loop: iterate through each collected timing sample.
        for sample in timing_data:
            # For the current sample, compute its m_temp and base_mont from scratch.
            # We need to simulate Montgomery exponentiation up to current known bits.

            # First compute base_mont
            base_mont = self.montgomery.to_montgomery(sample.ciphertext)
            current_result_mont = base_mont

            # Process all known bits (except the first '1')
            # The initial state for the loop is m^1.
            for bit_char in known_bits[1:]:
                current_result_mont = self.montgomery.montgomery_multiply(current_result_mont, current_result_mont)
                if bit_char == '1':
                    current_result_mont = self.montgomery.montgomery_multiply(current_result_mont, base_mont)

            # Now, we can compute m_temp
            m_temp = current_result_mont

            # The next operation in the algorithm is always a square.
            squared_m_temp = self.montgomery.montgomery_multiply(m_temp, m_temp)

            # Hypothesis: next bit is 1
            h1_mult = self.montgomery.montgomery_multiply(squared_m_temp, base_mont)
            if self.oracle.predict_reduction_needed(h1_mult, h1_mult):
                M1.append(sample.timing)
            else:
                M2.append(sample.timing)

            # Hypothesis: next bit is 0
            if self.oracle.predict_reduction_needed(squared_m_temp, squared_m_temp):
                M3.append(sample.timing)
            else:
                M4.append(sample.timing)

        # After partitioning all samples, compare the statistical differences between hypotheses
        diff_hyp1 = abs(np.mean(M1) - np.mean(M2)) if M1 and M2 else 0
        diff_hyp0 = abs(np.mean(M3) - np.mean(M4)) if M3 and M4 else 0

        if self.verbose:
            print(f"     -> H1 (bit=1) diff: {diff_hyp1:.4e} | H0 (bit=0) diff: {diff_hyp0:.4e}")

        return "1" if diff_hyp1 > diff_hyp0 else "0"

    def _trim_key(self, candidate_key: str, public_key: RSAPublicKey) -> str:
        """
        Finds the longest valid key by trimming bits from a raw candidate key.

        Since the exact length of the private exponent is not known, we might have
        recovered a few extraneous bits.
        This method starts with the full-length recovered key and shortens it one bit at a time
        until it finds a version that is functionally correct.

        Args:
            candidate_key (str): The potentially oversized key recovered from the raw attack.
            public_key (RSAPublicKey): The public key used for validation.

        Returns:
            str: The shortest possible functional key found, or the candidate key if none works.
        """
        if self.verbose:
            print(f"   Validating and trimming raw key of length {len(candidate_key)}...")

        # Starts with the full length private exponent and trim up to three bits
        for length in range(len(candidate_key), len(candidate_key) - 3, -1):
            candidate_key = candidate_key[:length]
            if self._is_key_valid(candidate_key, public_key):
                if self.verbose:
                    if len(candidate_key) == len(candidate_key):
                        print("     -> Full key is functionally valid.")
                    else:
                        print(f"     -> Found functional key of length {len(candidate_key)} after trimming.")
                return candidate_key

        if self.verbose:
            print("     -> No functional key found after trimming. Returning raw key.")
        return candidate_key

    def _is_key_valid(self, key_bits: str, public_key: RSAPublicKey) -> bool:
        """
        Tests if a candidate private key is functionally valid.

        Args:
            key_bits (str): The bits used to validate the private key.
            public_key (RSAPublicKey): The public key used for validation.

        Returns:
            bool: Whether the private key is functionally valid.
        """
        if not key_bits:  # A key cannot be empty
            return False

        try:
            d = int(key_bits, 2)
            test_message = 12345  # Use a fixed, deterministic message for testing

            # Check if (m^e)^d mod n == m
            ciphertext = pow(test_message, public_key.e, public_key.n)
            decrypted = pow(ciphertext, d, public_key.n)

            return decrypted == test_message
        except (ValueError, OverflowError):
            # Handles cases where key_bits is not a valid binary string or 'd' is too large
            return False

