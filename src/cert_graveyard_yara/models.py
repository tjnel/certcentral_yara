"""Data models for certificate records."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path


class ChangeType(Enum):
    """Type of change detected in certificate records."""

    ADDED = "added"
    MODIFIED = "modified"
    REMOVED = "removed"


@dataclass
class CertificateRecord:
    """Represents a compromised certificate from CertCentral.

    Attributes:
        hash: The file hash associated with the compromised certificate.
        malware_name: Name of the malware using this certificate.
        malware_type: Type/category of the malware.
        malware_notes: Additional notes about the malware.
        signer: Name of the certificate signer.
        cert_issuer_short: Short name of the certificate issuer.
        cert_issuer: Full name of the certificate issuer.
        cert_serial: Serial number of the certificate.
        cert_thumbprint: Thumbprint/fingerprint of the certificate.
        cert_valid_from: Certificate validity start date.
        cert_valid_to: Certificate validity end date.
        country: Country from certificate subject.
        state: State/province from certificate subject.
        locality: Locality/city from certificate subject.
        email: Email from certificate subject.
        rdn_serial_number: RDN serial number from certificate.
    """

    hash: str
    cert_serial: str
    malware_name: str = "Unknown"
    malware_type: str = "Unknown"
    malware_notes: str = ""
    signer: str = ""
    cert_issuer_short: str = "Unknown"
    cert_issuer: str = ""
    cert_thumbprint: str = ""
    cert_valid_from: str = ""
    cert_valid_to: str = ""
    country: str = ""
    state: str = ""
    locality: str = ""
    email: str = ""
    rdn_serial_number: str = ""

    def __post_init__(self) -> None:
        """Validate required fields."""
        if not self.hash:
            raise ValueError("Hash is required")
        if not self.cert_serial:
            raise ValueError("Certificate serial is required")

    @property
    def unique_id(self) -> str:
        """Generate a unique identifier for this record."""
        return f"{self.cert_serial}_{self.hash[:8]}"


@dataclass
class ValidationResult:
    """Result of YARA rule validation.

    Attributes:
        file_path: Path to the validated rule file.
        is_valid: Whether the rule passed validation.
        engine: Validation engine used ('yara' or 'yara-x').
        error_message: Error message if validation failed.
    """

    file_path: str
    is_valid: bool
    engine: str  # 'yara' or 'yara-x'
    error_message: str | None = None


@dataclass
class ChangelogEntry:
    """Represents a changelog entry for certificate changes.

    Attributes:
        date: Date of the change.
        change_type: Type of change (added, modified, removed).
        rule_name: Name of the YARA rule affected.
        description: Brief description of the change.
        certificate_serial: Serial number of the affected certificate.
    """

    date: datetime
    change_type: ChangeType
    rule_name: str
    description: str
    certificate_serial: str


@dataclass
class CSVChangeStatus:
    """Status of CSV change detection.

    Attributes:
        has_changed: Whether the CSV has changed.
        new_hash: SHA256 hash of the new CSV.
        old_hash: SHA256 hash of the previous CSV (if exists).
        new_records: List of new certificate records.
        modified_records: List of modified certificate records.
        removed_records: List of removed certificate records.
    """

    has_changed: bool
    new_hash: str
    old_hash: str | None = None
    new_records: list["CertificateRecord"] | None = None
    modified_records: list["CertificateRecord"] | None = None
    removed_records: list["CertificateRecord"] | None = None


@dataclass
class GenerationResult:
    """Result of YARA rule generation.

    Attributes:
        rule_path: Path to the generated rule file.
        rule_name: Name of the generated rule.
        certificate_serial: Serial of the certificate used.
        success: Whether generation was successful.
        error_message: Error message if generation failed.
    """

    rule_path: Path
    rule_name: str
    certificate_serial: str
    success: bool
    error_message: str | None = None

