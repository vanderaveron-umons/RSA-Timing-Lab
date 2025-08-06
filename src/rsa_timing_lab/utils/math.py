import random

def is_prime(n: int, iterations: int = 10) -> bool:
    """
    Miller-Rabin probabilistic primality test.

    Args:
        n (int): The number to test for primality.
        iterations (int): Number of iterations to perform (higher = more accurate).

    Returns:
        bool: True if n is probably prime, False if n is definitely composite.
    """

    # Handle trivial cases
    if n < 2:
        return False

    if n in (2, 3):
        return True

    if n % 2 == 0:
        return False

    # Write n-1 as d * 2^r where d is odd
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Perform Miller-Rabin test iterations
    for _ in range(iterations):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue

        # Square x repeatedly r-1 times
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else:
            # If we never found x == n-1, n is composite
            return False
    return True


def generate_rsa_prime(bits: int, max_attempts: int = 10000) -> int:
    """
    Generate a random prime number suitable for RSA (must be odd)
    with exactly the specified bit length.

    Args:
        bits (int): The desired bit length of the prime.
        max_attempts (int): Maximum number of candidates to try.

    Returns:
        int: A prime number with exactly 'bits' bits

    Raises:
        RuntimeError: If no prime found within max_attempts
    """
    for _ in range(max_attempts):
        # Generate random number with exact bit length
        # Set MSB to 1 (ensures exact bit length) and LSB to 1 (ensures odd)
        p = random.getrandbits(bits) | (1 << bits - 1) | 1
        if is_prime(p):
            return p
    raise RuntimeError(f"Unable to generate a {bits} bits prime after {max_attempts} attempts.")
