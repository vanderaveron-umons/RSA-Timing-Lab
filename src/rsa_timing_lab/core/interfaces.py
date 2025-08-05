from abc import ABC, abstractmethod
from typing import Tuple, Optional

from .models import RSAPublicKey, RSAKey, TimingData, AttackResult

class TimedRSAInterface(ABC):
    """
    Abstract interface for RSA implementations that measure execution time.

    This contract requires implementing timed encryption and decryption.
    It provides concrete implementations for signing and verification,
    as they are mathematically equivalent to decryption and encryption.
    """
    @abstractmethod
    def timed_encrypt(self, message: int, public_key: RSAPublicKey) -> Tuple[int, float]:
        """
        Encrypts the given message using the public key.

        Args:
            message (int): The message to encrypt (must be < n).
            public_key (RSAPublicKey): The RSA public key to use.

        Returns:
            (int, float): A tuple containing the encrypted ciphertext and the time taken for the operation (in seconds).
        """
        pass


    @abstractmethod
    def timed_decrypt(self, ciphertext: int, private_key: RSAKey) -> Tuple[int, float]:
        """
        Decrypts the given ciphertext using the private key.

        Args:
            ciphertext (int): The ciphertext to decrypt.
            private_key (RSAKey): The RSA private key to use.

        Returns:
        (int, float): A tuple containing the decrypted message and the time taken for the operation (in seconds).
        """
        pass

    def timed_sign(self, message: int, private_key: RSAKey) -> Tuple[int, float]:
        """
        Signs the given message using the private key.

        This method relies on the implementation of timed_decrypt,
        as RSA signing is mathematically equivalent to decryption.

        Args:
            message (int): The message to sign.
            private_key (RSAKey): The RSA private key to use for signing.

        Returns:
            (int, float): A tuple containing the signature and the time taken.
        """
        # The signing operation is the same as decryption
        return self.timed_decrypt(message, private_key)

    def timed_verify(self, signature: int, message: int, public_key: RSAPublicKey) -> Tuple[bool, float]:
        """
        Verifies the signature against the original message.

        This method relies on the implementation of timed_encrypt.

        Args:
            signature (int): The signature to verify.
            message (int): The original message.
            public_key (RSAPublicKey): The RSA public key to use for verification.

        Returns:
            (bool, float): A tuple containing a boolean (True if the signature valid) and the time taken.
        """
        # The verification operation is encryption followed by a comparison
        recovered_message, timing = self.timed_encrypt(signature, public_key)
        is_valid = (recovered_message == message)
        return is_valid, timing


class TimingAttackInterface(ABC):
    """
    Abstract interface for timing attack implementations.
    Defines the contract that all attack algorithms must follow.
    """

    @classmethod
    @abstractmethod
    def from_data(cls, public_key: RSAPublicKey, timing_data: list[TimingData], **kwargs) -> 'TimingAttackInterface':
        """
        A factory method to create an attack instance from collected data.

        Args:
            public_key (RSAPublicKey): The target's public key.
            timing_data (List[TimingData]) : A list of collected timing samples.
            kwargs: Additional attack-specific parameters.

        Returns:
            A configured instance of the attack class.
        """
        pass

    @abstractmethod
    def attack(self, limit_max_samples: Optional[int] = None) -> AttackResult:
        """
        Executes the timing attack to recover the private key.

        Args:
            limit_max_samples (int, optional): The maximum number of timing samples to use. Defaults to None, which uses all samples.

        Returns:
            An AttackResult object with the outcome.
        """
        pass