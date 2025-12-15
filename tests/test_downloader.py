"""Tests for the downloader module."""

import hashlib
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from cert_graveyard_yara.downloader import (
    DownloadError,
    calculate_hash,
    download_csv,
    get_stored_hash,
    has_csv_changed,
    save_hash,
)


class TestCalculateHash:
    """Tests for calculate_hash function."""

    def test_calculate_hash_success(self, temp_dir: Path) -> None:
        """Test calculating hash of a file."""
        test_file = temp_dir / "test.txt"
        content = b"test content for hashing"
        test_file.write_bytes(content)

        expected_hash = hashlib.sha256(content).hexdigest()
        result = calculate_hash(test_file)

        assert result == expected_hash

    def test_calculate_hash_large_file(self, temp_dir: Path) -> None:
        """Test calculating hash of a larger file."""
        test_file = temp_dir / "large.txt"
        # Create a file larger than the chunk size (8192 bytes)
        content = b"x" * 20000
        test_file.write_bytes(content)

        expected_hash = hashlib.sha256(content).hexdigest()
        result = calculate_hash(test_file)

        assert result == expected_hash

    def test_calculate_hash_file_not_found(self, temp_dir: Path) -> None:
        """Test that FileNotFoundError is raised for missing files."""
        nonexistent = temp_dir / "nonexistent.txt"

        with pytest.raises(FileNotFoundError):
            calculate_hash(nonexistent)


class TestHasCsvChanged:
    """Tests for has_csv_changed function."""

    def test_has_csv_changed_true(self, temp_dir: Path) -> None:
        """Test detection of changed CSV."""
        hash_file = temp_dir / ".csv_hash"
        hash_file.write_text("old_hash_value")

        result = has_csv_changed("new_hash_value", hash_file)

        assert result is True

    def test_has_csv_changed_false(self, temp_dir: Path) -> None:
        """Test detection of unchanged CSV."""
        hash_file = temp_dir / ".csv_hash"
        hash_file.write_text("same_hash_value")

        result = has_csv_changed("same_hash_value", hash_file)

        assert result is False

    def test_has_csv_changed_no_hash_file(self, temp_dir: Path) -> None:
        """Test that missing hash file returns True (changed)."""
        hash_file = temp_dir / ".csv_hash"
        # Don't create the file

        result = has_csv_changed("any_hash", hash_file)

        assert result is True


class TestSaveHash:
    """Tests for save_hash function."""

    def test_save_hash_creates_file(self, temp_dir: Path) -> None:
        """Test that save_hash creates the hash file."""
        hash_file = temp_dir / ".csv_hash"
        hash_value = "test_hash_123"

        save_hash(hash_value, hash_file)

        assert hash_file.exists()
        assert hash_file.read_text() == hash_value

    def test_save_hash_creates_parent_dirs(self, temp_dir: Path) -> None:
        """Test that save_hash creates parent directories."""
        hash_file = temp_dir / "subdir" / "nested" / ".csv_hash"
        hash_value = "nested_hash"

        save_hash(hash_value, hash_file)

        assert hash_file.exists()
        assert hash_file.read_text() == hash_value


class TestGetStoredHash:
    """Tests for get_stored_hash function."""

    def test_get_stored_hash_exists(self, temp_dir: Path) -> None:
        """Test getting stored hash when file exists."""
        hash_file = temp_dir / ".csv_hash"
        hash_file.write_text("stored_hash_value")

        result = get_stored_hash(hash_file)

        assert result == "stored_hash_value"

    def test_get_stored_hash_not_exists(self, temp_dir: Path) -> None:
        """Test getting stored hash when file doesn't exist."""
        hash_file = temp_dir / ".csv_hash"

        result = get_stored_hash(hash_file)

        assert result is None


class TestDownloadCsv:
    """Tests for download_csv function."""

    @pytest.mark.asyncio
    async def test_download_csv_success(self, temp_dir: Path) -> None:
        """Test successful CSV download."""
        output_path = temp_dir / "test.csv"
        csv_content = b"Hash,Serial\ntest,123"

        mock_response = AsyncMock()
        mock_response.content = csv_content
        mock_response.raise_for_status = lambda: None

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            mock_instance.__aenter__.return_value = mock_instance
            mock_instance.__aexit__.return_value = None
            mock_client.return_value = mock_instance

            result = await download_csv(
                url="https://example.com/test.csv",
                output_path=output_path,
            )

            assert result == output_path
            assert output_path.exists()
            assert output_path.read_bytes() == csv_content

    @pytest.mark.asyncio
    async def test_download_csv_network_error(self, temp_dir: Path) -> None:
        """Test download with network error and retries."""
        output_path = temp_dir / "test.csv"

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get.side_effect = httpx.RequestError("Connection failed")
            mock_instance.__aenter__.return_value = mock_instance
            mock_instance.__aexit__.return_value = None
            mock_client.return_value = mock_instance

            with pytest.raises(DownloadError) as exc_info:
                await download_csv(
                    url="https://example.com/test.csv",
                    output_path=output_path,
                    max_retries=2,
                )

            assert "Failed to download CSV after 2 attempts" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_download_csv_http_error(self, temp_dir: Path) -> None:
        """Test download with HTTP error response."""
        output_path = temp_dir / "test.csv"

        mock_response = AsyncMock()
        mock_response.status_code = 404
        http_error = httpx.HTTPStatusError("Not Found", request=None, response=mock_response)
        mock_response.raise_for_status.side_effect = http_error

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            mock_instance.__aenter__.return_value = mock_instance
            mock_instance.__aexit__.return_value = None
            mock_client.return_value = mock_instance

            with pytest.raises(DownloadError):
                await download_csv(
                    url="https://example.com/test.csv",
                    output_path=output_path,
                    max_retries=1,
                )

