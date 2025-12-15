"""Changelog management module."""

import logging
import re
from datetime import datetime
from pathlib import Path

from .generator import generate_rule_name
from .models import CertificateRecord, ChangelogEntry, ChangeType

logger = logging.getLogger(__name__)

# Default changelog path
DEFAULT_CHANGELOG_PATH = Path("CHANGELOG.md")

# Changelog header template
CHANGELOG_HEADER = """# Changelog

All notable changes to the CertCentral YARA rules will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

"""


def generate_changelog_entry(
    record: CertificateRecord,
    change_type: ChangeType,
    index: int = 0,
) -> ChangelogEntry:
    """Generate a changelog entry for a certificate record.

    Args:
        record: Certificate record.
        change_type: Type of change.
        index: Index for rule naming.

    Returns:
        ChangelogEntry object.
    """
    rule_name = generate_rule_name(record, index)

    # Create description based on change type
    if change_type == ChangeType.ADDED:
        description = f"{record.malware_name} - {record.cert_issuer_short}"
    elif change_type == ChangeType.MODIFIED:
        description = f"Updated metadata for {record.malware_name}"
    else:
        description = f"Removed {record.malware_name} rule"

    return ChangelogEntry(
        date=datetime.now(),
        change_type=change_type,
        rule_name=rule_name,
        description=description,
        certificate_serial=record.cert_serial,
    )


def format_changelog_entries(entries: list[ChangelogEntry], version: str | None = None) -> str:
    """Format changelog entries into markdown.

    Args:
        entries: List of changelog entries.
        version: Version string (defaults to date-based).

    Returns:
        Formatted markdown string.
    """
    if not entries:
        return ""

    if version is None:
        version = datetime.now().strftime("%Y.%m.%d")

    date_str = datetime.now().strftime("%Y-%m-%d")

    lines = [f"## [{version}] - {date_str}", ""]

    # Group by change type
    added = [e for e in entries if e.change_type == ChangeType.ADDED]
    modified = [e for e in entries if e.change_type == ChangeType.MODIFIED]
    removed = [e for e in entries if e.change_type == ChangeType.REMOVED]

    if added:
        lines.append("### Added")
        for entry in added:
            lines.append(f"- {entry.rule_name} ({entry.description})")
        lines.append("")

    if modified:
        lines.append("### Modified")
        for entry in modified:
            lines.append(f"- {entry.rule_name} ({entry.description})")
        lines.append("")

    if removed:
        lines.append("### Removed")
        for entry in removed:
            lines.append(f"- {entry.rule_name} ({entry.description})")
        lines.append("")

    return "\n".join(lines)


def read_changelog(changelog_path: Path | None = None) -> str:
    """Read the current changelog content.

    Args:
        changelog_path: Path to the changelog file.

    Returns:
        Current changelog content or empty header if not exists.
    """
    if changelog_path is None:
        changelog_path = DEFAULT_CHANGELOG_PATH

    if not changelog_path.exists():
        return CHANGELOG_HEADER

    return changelog_path.read_text(encoding="utf-8")


def update_changelog(
    entries: list[ChangelogEntry],
    changelog_path: Path | None = None,
    version: str | None = None,
) -> Path:
    """Update the changelog with new entries.

    Args:
        entries: List of changelog entries to add.
        changelog_path: Path to the changelog file.
        version: Version string for the release.

    Returns:
        Path to the updated changelog.
    """
    if changelog_path is None:
        changelog_path = DEFAULT_CHANGELOG_PATH

    if not entries:
        logger.info("No changelog entries to add")
        return changelog_path

    # Read existing content
    existing_content = read_changelog(changelog_path)

    # Format new entries
    new_section = format_changelog_entries(entries, version)

    # Insert new section after header
    if "## [" in existing_content:
        # Find first version section and insert before it
        match = re.search(r"(## \[)", existing_content)
        if match:
            insert_pos = match.start()
            updated_content = (
                existing_content[:insert_pos] + new_section + "\n" + existing_content[insert_pos:]
            )
        else:
            updated_content = existing_content + "\n" + new_section
    else:
        # No existing versions, append after header
        updated_content = existing_content.rstrip() + "\n\n" + new_section

    # Write updated changelog
    changelog_path.parent.mkdir(parents=True, exist_ok=True)
    changelog_path.write_text(updated_content, encoding="utf-8")

    logger.info(f"Updated changelog with {len(entries)} entries: {changelog_path}")
    return changelog_path


def generate_release_notes(
    added: list[CertificateRecord],
    modified: list[CertificateRecord],
    removed: list[CertificateRecord],
    output_path: Path | None = None,
) -> Path:
    """Generate release notes for a GitHub release.

    Args:
        added: List of added certificate records.
        modified: List of modified certificate records.
        removed: List of removed certificate records.
        output_path: Path to save release notes.

    Returns:
        Path to the generated release notes file.
    """
    if output_path is None:
        output_path = Path("RELEASE_NOTES.md")

    total_rules = len(added) + len(modified)  # removed don't count toward total
    date_str = datetime.now().strftime("%Y-%m-%d")

    lines = [
        f"# CertCentral YARA Rules Release - {date_str}",
        "",
        "## Summary",
        "",
        f"- **Total Rules**: {total_rules}",
        f"- **New Rules**: {len(added)}",
        f"- **Updated Rules**: {len(modified)}",
        f"- **Removed Rules**: {len(removed)}",
        "",
        "## Contents",
        "",
        "- `MAL_Compromised_Cert_*.yara` - Combined YARA ruleset",
        "- `cert_central_yara_rules.zip` - Individual rule files",
        "",
        "## Usage",
        "",
        "```bash",
        "# Scan with combined ruleset",
        "yara MAL_Compromised_Cert_*.yara /path/to/scan",
        "",
        "# Or extract individual rules",
        "unzip cert_central_yara_rules.zip -d rules/",
        "yara rules/*.yara /path/to/scan",
        "```",
        "",
        "## Source",
        "",
        "Rules generated from [CertCentral](https://certcentral.org) "
        "compromised certificate database.",
        "",
    ]

    if added:
        lines.extend([
            "## New Rules",
            "",
        ])
        for record in added[:20]:  # Limit to 20 entries
            rule_name = generate_rule_name(record)
            lines.append(f"- {rule_name}")
        if len(added) > 20:
            lines.append(f"- ... and {len(added) - 20} more")
        lines.append("")

    if modified:
        lines.extend([
            "## Updated Rules",
            "",
        ])
        for record in modified[:10]:
            rule_name = generate_rule_name(record)
            lines.append(f"- {rule_name}")
        if len(modified) > 10:
            lines.append(f"- ... and {len(modified) - 10} more")
        lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")
    logger.info(f"Generated release notes: {output_path}")

    return output_path


def detect_changes(
    old_records: list[CertificateRecord],
    new_records: list[CertificateRecord],
) -> list[ChangelogEntry]:
    """Detect changes between old and new records and generate changelog entries.

    Args:
        old_records: Previous list of records.
        new_records: New list of records.

    Returns:
        List of changelog entries for all changes.
    """
    from .parser import compare_records

    added, modified, removed = compare_records(old_records, new_records)

    entries = []

    # Create record index for new records to get proper indices
    new_record_indices = {r.unique_id: i for i, r in enumerate(new_records)}
    old_record_indices = {r.unique_id: i for i, r in enumerate(old_records)}

    for record in added:
        idx = new_record_indices.get(record.unique_id, 0)
        entries.append(generate_changelog_entry(record, ChangeType.ADDED, idx))

    for record in modified:
        idx = new_record_indices.get(record.unique_id, 0)
        entries.append(generate_changelog_entry(record, ChangeType.MODIFIED, idx))

    for record in removed:
        idx = old_record_indices.get(record.unique_id, 0)
        entries.append(generate_changelog_entry(record, ChangeType.REMOVED, idx))

    logger.info(
        f"Detected changes: {len(added)} added, {len(modified)} modified, {len(removed)} removed"
    )

    return entries

