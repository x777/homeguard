"""OS fingerprinting based on TTL values."""


def guess_os_from_ttl(ttl: int) -> str:
    """
    Guess operating system based on TTL value.

    TTL decrements by 1 per router hop, so we use ranges:
    - 64 (or 1-64): Linux/macOS/FreeBSD
    - 128 (or 65-128): Windows
    - 255 (or 129-255): Cisco/Network devices
    """
    if ttl <= 0:
        return "Unknown"
    elif ttl <= 64:
        return "Linux/macOS/Unix"
    elif ttl <= 128:
        return "Windows"
    else:
        return "Network Device (Cisco/Router)"


def get_os_details(ttl: int) -> dict:
    """Get detailed OS information based on TTL."""
    os_guess = guess_os_from_ttl(ttl)

    if ttl <= 64:
        original_ttl = 64
    elif ttl <= 128:
        original_ttl = 128
    else:
        original_ttl = 255

    hops = original_ttl - ttl

    return {
        "os_guess": os_guess,
        "ttl_observed": ttl,
        "ttl_original": original_ttl,
        "estimated_hops": hops,
    }
