"""CSV parsing and validation module."""

import logging
from pathlib import Path

import pandas as pd

from .models import CertificateRecord

logger = logging.getLogger(__name__)

# Expected CSV column names mapping to CertificateRecord fields
COLUMN_MAPPING = {
    "Hash": "hash",
    "Malware": "malware_name",
    "Malware Type": "malware_type",
    "Malware Notes": "malware_notes",
    "Signer": "signer",
    "Issuer Short": "cert_issuer_short",
    "Issuer": "cert_issuer",
    "Serial": "cert_serial",
    "Thumbprint": "cert_thumbprint",
    "Valid From": "cert_valid_from",
    "Valid To": "cert_valid_to",
    "Country": "country",
    "State": "state",
    "Locality": "locality",
    "Email": "email",
    "RDN Serial Number": "rdn_serial_number",
}

# Required columns that must be present
REQUIRED_COLUMNS = {"Hash", "Serial"}


class ParseError(Exception):
    """Exception raised when CSV parsing fails."""

    pass


def parse_csv(file_path: Path) -> list[CertificateRecord]:
    """Parse CertCentral CSV into CertificateRecord objects.

    Args:
        file_path: Path to the CSV file.

    Returns:
        List of CertificateRecord objects.

    Raises:
        ParseError: If the CSV is missing required columns.
        FileNotFoundError: If the CSV file doesn't exist.
    """
    if not file_path.exists():
        raise FileNotFoundError(f"CSV file not found: {file_path}")

    logger.info(f"Parsing CSV file: {file_path}")

    try:
        df = pd.read_csv(file_path, dtype=str)
    except Exception as e:
        raise ParseError(f"Failed to read CSV file: {e}") from e

    # Validate required columns
    missing_columns = REQUIRED_COLUMNS - set(df.columns)
    if missing_columns:
        raise ParseError(f"CSV missing required columns: {missing_columns}")

    # Check for optional columns and warn if missing
    optional_missing = set(COLUMN_MAPPING.keys()) - set(df.columns) - REQUIRED_COLUMNS
    if optional_missing:
        logger.warning(f"CSV missing optional columns: {optional_missing}")

    records: list[CertificateRecord] = []
    invalid_count = 0

    for idx, row in df.iterrows():
        try:
            row_idx = int(idx) if isinstance(idx, int) else 0
            record = _row_to_record(row, row_idx)
            if record is not None:
                records.append(record)
        except ValueError as e:
            invalid_count += 1
            logger.warning(f"Skipping invalid row {idx}: {e}")

    logger.info(
        f"Parsed {len(records)} valid records from {len(df)} rows "
        f"({invalid_count} invalid rows skipped)"
    )

    return records


def _row_to_record(row: "pd.Series[str]", index: int) -> CertificateRecord | None:
    """Convert a DataFrame row to a CertificateRecord.

    Args:
        row: Pandas Series representing a CSV row.
        index: Row index for error reporting.

    Returns:
        CertificateRecord if valid, None if required fields are missing.

    Raises:
        ValueError: If required fields are invalid.
    """

    def get_value(column: str, default: str = "") -> str:
        """Get a string value from the row, handling NaN and empty values."""
        if column not in row.index:
            return default
        value = row[column]
        if pd.isna(value) or str(value).strip() == "" or str(value) == "nan":
            return default
        return str(value).strip()

    # Get required fields
    hash_value = get_value("Hash")
    serial_value = get_value("Serial")

    # Validate required fields
    if not hash_value:
        raise ValueError("Hash is required")
    if not serial_value:
        raise ValueError("Serial is required")

    return CertificateRecord(
        hash=hash_value,
        cert_serial=serial_value,
        malware_name=get_value("Malware", "Unknown"),
        malware_type=get_value("Malware Type", "Unknown"),
        malware_notes=get_value("Malware Notes"),
        signer=get_value("Signer"),
        cert_issuer_short=get_value("Issuer Short", "Unknown"),
        cert_issuer=get_value("Issuer"),
        cert_thumbprint=get_value("Thumbprint"),
        cert_valid_from=get_value("Valid From"),
        cert_valid_to=get_value("Valid To"),
        country=get_value("Country"),
        state=get_value("State"),
        locality=get_value("Locality"),
        email=get_value("Email"),
        rdn_serial_number=get_value("RDN Serial Number"),
    )


def compare_records(
    old_records: list[CertificateRecord], new_records: list[CertificateRecord]
) -> tuple[list[CertificateRecord], list[CertificateRecord], list[CertificateRecord]]:
    """Compare old and new records to find changes.

    Args:
        old_records: Previous list of certificate records.
        new_records: New list of certificate records.

    Returns:
        Tuple of (added, modified, removed) record lists.
    """
    old_by_id = {r.unique_id: r for r in old_records}
    new_by_id = {r.unique_id: r for r in new_records}

    old_ids = set(old_by_id.keys())
    new_ids = set(new_by_id.keys())

    added_ids = new_ids - old_ids
    removed_ids = old_ids - new_ids
    common_ids = old_ids & new_ids

    added = [new_by_id[id_] for id_ in added_ids]
    removed = [old_by_id[id_] for id_ in removed_ids]

    # Check for modifications in common records
    modified = []
    for id_ in common_ids:
        old_record = old_by_id[id_]
        new_record = new_by_id[id_]
        if _record_changed(old_record, new_record):
            modified.append(new_record)

    logger.info(
        f"Record comparison: {len(added)} added, "
        f"{len(modified)} modified, {len(removed)} removed"
    )

    return added, modified, removed


def _record_changed(old: CertificateRecord, new: CertificateRecord) -> bool:
    """Check if a record has been modified.

    Args:
        old: Previous record.
        new: New record.

    Returns:
        True if any field has changed.
    """
    # Compare all fields except unique_id (derived from hash and serial)
    fields_to_compare = [
        "malware_name",
        "malware_type",
        "malware_notes",
        "signer",
        "cert_issuer_short",
        "cert_issuer",
        "cert_thumbprint",
        "cert_valid_from",
        "cert_valid_to",
        "country",
        "state",
        "locality",
        "email",
        "rdn_serial_number",
    ]

    return any(getattr(old, field) != getattr(new, field) for field in fields_to_compare)

