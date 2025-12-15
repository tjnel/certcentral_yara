"""Tests for the parser module."""

from pathlib import Path

import pytest

from cert_graveyard_yara.models import CertificateRecord
from cert_graveyard_yara.parser import (
    ParseError,
    compare_records,
    parse_csv,
)


class TestParseCsv:
    """Tests for parse_csv function."""

    def test_parse_csv_valid(self, sample_csv_file: Path) -> None:
        """Test parsing a valid CSV file."""
        records = parse_csv(sample_csv_file)

        assert len(records) == 2
        assert records[0].hash == "a1b2c3d4"
        assert records[0].malware_name == "Emotet"
        assert records[0].cert_serial == "0a1b2c3d"
        assert records[0].cert_issuer_short == "DigiCert"

        assert records[1].hash == "e5f6g7h8"
        assert records[1].malware_name == "Qakbot"

    def test_parse_csv_missing_optional_columns(
        self, temp_dir: Path, sample_csv_missing_columns: str
    ) -> None:
        """Test parsing CSV with missing optional columns."""
        csv_path = temp_dir / "minimal.csv"
        csv_path.write_text(sample_csv_missing_columns)

        records = parse_csv(csv_path)

        assert len(records) == 2
        assert records[0].hash == "a1b2c3d4"
        assert records[0].cert_serial == "0a1b2c3d"
        # Optional fields should have defaults
        assert records[0].malware_name == "Unknown"
        assert records[0].cert_issuer_short == "Unknown"

    def test_parse_csv_malformed_rows(
        self, temp_dir: Path, sample_csv_invalid_rows: str
    ) -> None:
        """Test parsing CSV with some invalid rows."""
        csv_path = temp_dir / "invalid.csv"
        csv_path.write_text(sample_csv_invalid_rows)

        records = parse_csv(csv_path)

        # Should skip invalid row (missing hash) and parse valid ones
        assert len(records) == 2
        assert records[0].hash == "a1b2c3d4"
        assert records[1].hash == "e5f6g7h8"

    def test_parse_csv_missing_required_columns(self, temp_dir: Path) -> None:
        """Test that missing required columns raises ParseError."""
        csv_path = temp_dir / "missing_required.csv"
        csv_path.write_text("Malware,Type\nEmotet,Trojan\n")

        with pytest.raises(ParseError) as exc_info:
            parse_csv(csv_path)

        assert "missing required columns" in str(exc_info.value).lower()

    def test_parse_csv_file_not_found(self, temp_dir: Path) -> None:
        """Test that missing file raises FileNotFoundError."""
        nonexistent = temp_dir / "nonexistent.csv"

        with pytest.raises(FileNotFoundError):
            parse_csv(nonexistent)

    def test_parse_csv_empty_values_use_defaults(self, temp_dir: Path) -> None:
        """Test that empty values get appropriate defaults."""
        header = (
            "Hash,Malware,Malware Type,Malware Notes,Signer,Issuer Short,Issuer,"
            "Serial,Thumbprint,Valid From,Valid To,Country,State,Locality,Email,RDN Serial Number"
        )
        row = "abc123,,,,,,DigiCert CA,def456,,,,,,,"
        csv_content = f"{header}\n{row}\n"
        csv_path = temp_dir / "empty_values.csv"
        csv_path.write_text(csv_content)

        records = parse_csv(csv_path)

        assert len(records) == 1
        assert records[0].hash == "abc123"
        assert records[0].malware_name == "Unknown"
        assert records[0].malware_type == "Unknown"
        assert records[0].cert_issuer_short == "Unknown"


class TestCertificateRecordValidation:
    """Tests for CertificateRecord validation."""

    def test_certificate_record_valid(self) -> None:
        """Test creating a valid certificate record."""
        record = CertificateRecord(
            hash="test_hash",
            cert_serial="test_serial",
        )
        assert record.hash == "test_hash"
        assert record.cert_serial == "test_serial"

    def test_certificate_record_missing_hash(self) -> None:
        """Test that missing hash raises ValueError."""
        with pytest.raises(ValueError) as exc_info:
            CertificateRecord(hash="", cert_serial="serial")
        assert "Hash is required" in str(exc_info.value)

    def test_certificate_record_missing_serial(self) -> None:
        """Test that missing serial raises ValueError."""
        with pytest.raises(ValueError) as exc_info:
            CertificateRecord(hash="hash", cert_serial="")
        assert "Certificate serial is required" in str(exc_info.value)

    def test_certificate_record_unique_id(self) -> None:
        """Test unique_id property generation."""
        record = CertificateRecord(
            hash="abcdef123456",
            cert_serial="serial123",
        )
        assert record.unique_id == "serial123_abcdef12"


class TestCompareRecords:
    """Tests for compare_records function."""

    def test_compare_records_detect_added(self) -> None:
        """Test detection of added records."""
        old_records: list[CertificateRecord] = []
        new_records = [
            CertificateRecord(hash="hash1", cert_serial="serial1"),
            CertificateRecord(hash="hash2", cert_serial="serial2"),
        ]

        added, modified, removed = compare_records(old_records, new_records)

        assert len(added) == 2
        assert len(modified) == 0
        assert len(removed) == 0

    def test_compare_records_detect_removed(self) -> None:
        """Test detection of removed records."""
        old_records = [
            CertificateRecord(hash="hash1", cert_serial="serial1"),
            CertificateRecord(hash="hash2", cert_serial="serial2"),
        ]
        new_records: list[CertificateRecord] = []

        added, modified, removed = compare_records(old_records, new_records)

        assert len(added) == 0
        assert len(modified) == 0
        assert len(removed) == 2

    def test_compare_records_detect_modified(self) -> None:
        """Test detection of modified records."""
        old_records = [
            CertificateRecord(
                hash="hash1",
                cert_serial="serial1",
                malware_name="OldName",
            ),
        ]
        new_records = [
            CertificateRecord(
                hash="hash1",
                cert_serial="serial1",
                malware_name="NewName",
            ),
        ]

        added, modified, removed = compare_records(old_records, new_records)

        assert len(added) == 0
        assert len(modified) == 1
        assert modified[0].malware_name == "NewName"
        assert len(removed) == 0

    def test_compare_records_mixed_changes(self) -> None:
        """Test detection of mixed changes."""
        old_records = [
            CertificateRecord(hash="hash1", cert_serial="serial1"),  # will be removed
            CertificateRecord(
                hash="hash2", cert_serial="serial2", malware_name="Old"
            ),  # will be modified
        ]
        new_records = [
            CertificateRecord(
                hash="hash2", cert_serial="serial2", malware_name="New"
            ),  # modified
            CertificateRecord(hash="hash3", cert_serial="serial3"),  # added
        ]

        added, modified, removed = compare_records(old_records, new_records)

        assert len(added) == 1
        assert added[0].hash == "hash3"
        assert len(modified) == 1
        assert modified[0].hash == "hash2"
        assert len(removed) == 1
        assert removed[0].hash == "hash1"

