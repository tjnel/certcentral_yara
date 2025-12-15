"""CSV download and change detection module."""

import asyncio
import hashlib
import logging
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

# CertGraveyard CSV download URL
CERTGRAVEYARD_CSV_URL = "https://certgraveyard.org/api/download_csv"

# Default headers to mimic a browser request
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/csv,application/csv,text/plain,*/*",
    "Accept-Language": "en-US,en;q=0.9",
}

# Default paths
DEFAULT_DATA_DIR = Path("data")
DEFAULT_CSV_FILENAME = "cert_graveyard_database.csv"
DEFAULT_HASH_FILENAME = ".csv_hash"


class DownloadError(Exception):
    """Exception raised when CSV download fails."""

    pass


async def download_csv(
    url: str = CERTGRAVEYARD_CSV_URL,
    output_path: Path | None = None,
    timeout: float = 60.0,
    max_retries: int = 3,
) -> Path:
    """Download CSV from CertGraveyard with retry logic.

    Args:
        url: URL to download CSV from.
        output_path: Path to save the downloaded CSV.
        timeout: Request timeout in seconds.
        max_retries: Maximum number of retry attempts.

    Returns:
        Path to the downloaded CSV file.

    Raises:
        DownloadError: If download fails after all retries.
    """
    if output_path is None:
        output_path = DEFAULT_DATA_DIR / DEFAULT_CSV_FILENAME

    # Ensure parent directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    last_error: Exception | None = None

    for attempt in range(max_retries):
        try:
            logger.info(f"Downloading CSV from {url} (attempt {attempt + 1}/{max_retries})")

            async with httpx.AsyncClient(timeout=timeout, headers=DEFAULT_HEADERS) as client:
                response = await client.get(url)
                response.raise_for_status()

                # Write content to file
                output_path.write_bytes(response.content)
                logger.info(f"Successfully downloaded CSV to {output_path}")
                return output_path

        except httpx.HTTPStatusError as e:
            last_error = e
            logger.warning(f"HTTP error {e.response.status_code}: {e}")
        except httpx.RequestError as e:
            last_error = e
            logger.warning(f"Request error: {e}")
        except Exception as e:
            last_error = e
            logger.warning(f"Unexpected error: {e}")

        if attempt < max_retries - 1:
            # Exponential backoff
            wait_time = 2 ** (attempt + 1)
            logger.info(f"Retrying in {wait_time} seconds...")
            await asyncio.sleep(wait_time)

    raise DownloadError(
        f"Failed to download CSV after {max_retries} attempts. Last error: {last_error}"
    )


def download_csv_sync(
    url: str = CERTGRAVEYARD_CSV_URL,
    output_path: Path | None = None,
    timeout: float = 60.0,
    max_retries: int = 3,
) -> Path:
    """Synchronous wrapper for download_csv.

    Args:
        url: URL to download CSV from.
        output_path: Path to save the downloaded CSV.
        timeout: Request timeout in seconds.
        max_retries: Maximum number of retry attempts.

    Returns:
        Path to the downloaded CSV file.

    Raises:
        DownloadError: If download fails after all retries.
    """
    return asyncio.run(download_csv(url, output_path, timeout, max_retries))


def calculate_hash(file_path: Path) -> str:
    """Calculate SHA256 hash of a file.

    Args:
        file_path: Path to the file to hash.

    Returns:
        Hexadecimal SHA256 hash string.

    Raises:
        FileNotFoundError: If the file doesn't exist.
    """
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as f:
        # Read in chunks for memory efficiency
        for chunk in iter(lambda: f.read(8192), b""):
            sha256_hash.update(chunk)

    return sha256_hash.hexdigest()


def has_csv_changed(new_hash: str, hash_file: Path | None = None) -> bool:
    """Check if the CSV has changed by comparing hashes.

    Args:
        new_hash: SHA256 hash of the new CSV.
        hash_file: Path to the file containing the previous hash.

    Returns:
        True if the CSV has changed (or no previous hash exists), False otherwise.
    """
    if hash_file is None:
        hash_file = DEFAULT_DATA_DIR / DEFAULT_HASH_FILENAME

    if not hash_file.exists():
        logger.info("No previous hash file found - treating as changed")
        return True

    try:
        old_hash = hash_file.read_text().strip()
        has_changed = old_hash != new_hash
        if has_changed:
            logger.info(f"CSV hash changed: {old_hash[:16]}... -> {new_hash[:16]}...")
        else:
            logger.info("CSV hash unchanged")
        return has_changed
    except Exception as e:
        logger.warning(f"Error reading hash file: {e}")
        return True


def save_hash(hash_value: str, hash_file: Path | None = None) -> None:
    """Save the CSV hash to a file.

    Args:
        hash_value: SHA256 hash to save.
        hash_file: Path to save the hash file.
    """
    if hash_file is None:
        hash_file = DEFAULT_DATA_DIR / DEFAULT_HASH_FILENAME

    hash_file.parent.mkdir(parents=True, exist_ok=True)
    hash_file.write_text(hash_value)
    logger.info(f"Saved hash to {hash_file}")


def get_stored_hash(hash_file: Path | None = None) -> str | None:
    """Get the previously stored CSV hash.

    Args:
        hash_file: Path to the hash file.

    Returns:
        The stored hash string, or None if not found.
    """
    if hash_file is None:
        hash_file = DEFAULT_DATA_DIR / DEFAULT_HASH_FILENAME

    if not hash_file.exists():
        return None

    try:
        return hash_file.read_text().strip()
    except Exception as e:
        logger.warning(f"Error reading hash file: {e}")
        return None

