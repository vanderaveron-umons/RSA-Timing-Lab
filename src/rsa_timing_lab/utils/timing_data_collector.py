import random
import time
from typing import List, Tuple, Optional

from rsa_timing_lab.core import TimedRSAInterface, RSAKey, TimingData


class TimingDataCollector:
    """
    Collects timing data for RSA decryption operations on a single key.
    Its sole responsibility is to generate and return timing samples.
    """

    def __init__(self, rsa_instance: TimedRSAInterface):
        self.rsa_instance = rsa_instance

    def collect_samples(
            self,
            key: RSAKey,
            num_samples: int,
            seed: Optional[int] = None
    ) -> Tuple[List[TimingData], float]:
        """
        Collects and returns timing samples for RSA decryption.

        Args:
            key (RSAKey): The key to use.
            num_samples (int): The number of samples to collect.
            seed (int, optional): The seed for the random number generator. Defaults to None.

        Returns:
            (List[TimingData], float): A tuple containing the timing samples and the time taken for the operation (in seconds).
        """
        if num_samples <= 0:
            raise ValueError("Number of samples must be positive.")
        if seed is not None:
            random.seed(seed)

        timing_data = []
        start_time = time.time()

        for _ in range(num_samples):
            plaintext = random.randrange(1, key.n)
            ciphertext, _ = self.rsa_instance.timed_encrypt(plaintext, key.public_key)
            _, decryption_time = self.rsa_instance.timed_decrypt(ciphertext, key)

            timing_data.append(TimingData(ciphertext, decryption_time))

        collection_time = time.time() - start_time
        return timing_data, collection_time