"""Pytest configuration and fixtures."""

import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

from cert_graveyard_yara.models import CertificateRecord


@pytest.fixture
def sample_record() -> CertificateRecord:
    """Create a sample certificate record for testing."""
    return CertificateRecord(
        hash="a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
        cert_serial="0a1b2c3d4e5f6a7b8c9d",
        malware_name="Emotet",
        malware_type="Trojan",
        malware_notes="Banking trojan dropper",
        signer="Acme Corp",
        cert_issuer_short="DigiCert",
        cert_issuer="DigiCert SHA2 Assured ID Code Signing CA",
        cert_thumbprint="ABC123DEF456",
        cert_valid_from="2024-01-15",
        cert_valid_to="2025-01-15",
        country="US",
        state="California",
        locality="San Francisco",
        email="dev@acme.com",
        rdn_serial_number="12345",
    )


@pytest.fixture
def sample_record_minimal() -> CertificateRecord:
    """Create a minimal certificate record with only required fields."""
    return CertificateRecord(
        hash="minimal_hash_123456789",
        cert_serial="0123456789abcdef",
    )


@pytest.fixture
def sample_records() -> list[CertificateRecord]:
    """Create a list of sample certificate records."""
    return [
        CertificateRecord(
            hash="hash1",
            cert_serial="serial1",
            malware_name="Malware1",
            cert_issuer_short="Issuer1",
        ),
        CertificateRecord(
            hash="hash2",
            cert_serial="serial2",
            malware_name="Malware2",
            cert_issuer_short="Issuer2",
        ),
        CertificateRecord(
            hash="hash3",
            cert_serial="serial3",
            malware_name="Malware3",
            cert_issuer_short="Issuer3",
        ),
    ]


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_csv_content() -> str:
    """Sample CSV content matching CertGraveyard format."""
    header = (
        "Hash,Malware,Malware Type,Malware Notes,Signer,Issuer Short,Issuer,"
        "Serial,Thumbprint,Valid From,Valid To,Country,State,Locality,Email,RDN Serial Number"
    )
    row1 = (
        "a1b2c3d4,Emotet,Trojan,Banking dropper,Acme Corp,DigiCert,DigiCert SHA2 CA,"
        "0a1b2c3d,ABC123,2024-01-15,2025-01-15,US,California,San Francisco,dev@acme.com,12345"
    )
    row2 = (
        "e5f6g7h8,Qakbot,Loader,Qakbot payload,Evil Corp,Sectigo,Sectigo RSA CA,"
        "4d5e6f7g,DEF456,2024-02-01,2025-02-01,RU,Moscow,,evil@corp.ru,67890"
    )
    return f"{header}\n{row1}\n{row2}\n"


@pytest.fixture
def sample_csv_file(temp_dir: Path, sample_csv_content: str) -> Path:
    """Create a sample CSV file."""
    csv_path = temp_dir / "test_database.csv"
    csv_path.write_text(sample_csv_content)
    return csv_path


@pytest.fixture
def sample_csv_missing_columns() -> str:
    """CSV content with missing optional columns."""
    return """Hash,Serial
a1b2c3d4,0a1b2c3d
e5f6g7h8,4d5e6f7g
"""


@pytest.fixture
def sample_csv_invalid_rows() -> str:
    """CSV content with some invalid rows."""
    header = (
        "Hash,Malware,Malware Type,Malware Notes,Signer,Issuer Short,Issuer,"
        "Serial,Thumbprint,Valid From,Valid To,Country,State,Locality,Email,RDN Serial Number"
    )
    row1 = (
        "a1b2c3d4,Emotet,Trojan,Banking dropper,Acme Corp,DigiCert,DigiCert SHA2 CA,"
        "0a1b2c3d,ABC123,2024-01-15,2025-01-15,US,California,San Francisco,dev@acme.com,12345"
    )
    row2 = (
        ",InvalidNoHash,Loader,Missing hash,,Sectigo,Sectigo RSA CA,"
        "4d5e6f7g,DEF456,2024-02-01,2025-02-01,RU,Moscow,,evil@corp.ru,67890"
    )
    row3 = (
        "e5f6g7h8,ValidRecord,Malware,Notes,Signer,Issuer,Full Issuer,"
        "serial123,thumb,2024-01-01,2025-01-01,US,NY,NYC,email@test.com,999"
    )
    return f"{header}\n{row1}\n{row2}\n{row3}\n"


@pytest.fixture
def valid_yara_rule() -> str:
    """A valid YARA rule for testing validation."""
    return '''import "pe"

rule Test_Valid_Rule {
   meta:
      description = "Test rule"
      author = "Test"

   condition:
      uint16(0) == 0x5a4d
}
'''


@pytest.fixture
def invalid_yara_rule() -> str:
    """An invalid YARA rule for testing validation."""
    return '''import "pe"

rule Invalid_Rule {
   meta:
      description = "Missing closing brace"
      author = "Test"

   condition:
      uint16(0) == 0x5a4d
// Missing closing brace
'''


@pytest.fixture
def valid_yara_file(temp_dir: Path, valid_yara_rule: str) -> Path:
    """Create a valid YARA rule file."""
    rule_path = temp_dir / "valid_rule.yara"
    rule_path.write_text(valid_yara_rule)
    return rule_path


@pytest.fixture
def invalid_yara_file(temp_dir: Path, invalid_yara_rule: str) -> Path:
    """Create an invalid YARA rule file."""
    rule_path = temp_dir / "invalid_rule.yara"
    rule_path.write_text(invalid_yara_rule)
    return rule_path

