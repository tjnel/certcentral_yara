"""Tests for the changelog module."""

from datetime import datetime
from pathlib import Path

from cert_graveyard_yara.changelog import (
    CHANGELOG_HEADER,
    detect_changes,
    format_changelog_entries,
    generate_changelog_entry,
    generate_release_notes,
    read_changelog,
    update_changelog,
)
from cert_graveyard_yara.models import CertificateRecord, ChangelogEntry, ChangeType


class TestGenerateChangelogEntry:
    """Tests for generate_changelog_entry function."""

    def test_generate_changelog_entry_added(self, sample_record: CertificateRecord) -> None:
        """Test generating entry for added record."""
        entry = generate_changelog_entry(sample_record, ChangeType.ADDED)

        assert entry.change_type == ChangeType.ADDED
        assert "Emotet" in entry.description
        assert entry.certificate_serial == sample_record.cert_serial
        assert "MAL_Compromised_Cert" in entry.rule_name

    def test_generate_changelog_entry_modified(self, sample_record: CertificateRecord) -> None:
        """Test generating entry for modified record."""
        entry = generate_changelog_entry(sample_record, ChangeType.MODIFIED)

        assert entry.change_type == ChangeType.MODIFIED
        assert "Updated" in entry.description

    def test_generate_changelog_entry_removed(self, sample_record: CertificateRecord) -> None:
        """Test generating entry for removed record."""
        entry = generate_changelog_entry(sample_record, ChangeType.REMOVED)

        assert entry.change_type == ChangeType.REMOVED
        assert "Removed" in entry.description


class TestFormatChangelogEntries:
    """Tests for format_changelog_entries function."""

    def test_format_changelog_entries_empty(self) -> None:
        """Test formatting empty entries list."""
        result = format_changelog_entries([])
        assert result == ""

    def test_format_changelog_entries_added_only(self) -> None:
        """Test formatting with only added entries."""
        entries = [
            ChangelogEntry(
                date=datetime.now(),
                change_type=ChangeType.ADDED,
                rule_name="MAL_Test_Rule",
                description="Test malware",
                certificate_serial="abc123",
            ),
        ]

        result = format_changelog_entries(entries, version="2025.12.14")

        assert "## [2025.12.14]" in result
        assert "### Added" in result
        assert "MAL_Test_Rule" in result
        assert "### Modified" not in result
        assert "### Removed" not in result

    def test_format_changelog_entries_mixed(self) -> None:
        """Test formatting with mixed entry types."""
        entries = [
            ChangelogEntry(
                date=datetime.now(),
                change_type=ChangeType.ADDED,
                rule_name="Added_Rule",
                description="New rule",
                certificate_serial="abc",
            ),
            ChangelogEntry(
                date=datetime.now(),
                change_type=ChangeType.MODIFIED,
                rule_name="Modified_Rule",
                description="Updated rule",
                certificate_serial="def",
            ),
            ChangelogEntry(
                date=datetime.now(),
                change_type=ChangeType.REMOVED,
                rule_name="Removed_Rule",
                description="Deleted rule",
                certificate_serial="ghi",
            ),
        ]

        result = format_changelog_entries(entries)

        assert "### Added" in result
        assert "Added_Rule" in result
        assert "### Modified" in result
        assert "Modified_Rule" in result
        assert "### Removed" in result
        assert "Removed_Rule" in result


class TestReadChangelog:
    """Tests for read_changelog function."""

    def test_read_changelog_exists(self, temp_dir: Path) -> None:
        """Test reading existing changelog."""
        changelog_path = temp_dir / "CHANGELOG.md"
        changelog_path.write_text("# Existing Changelog\n\nContent here.")

        result = read_changelog(changelog_path)

        assert "Existing Changelog" in result
        assert "Content here" in result

    def test_read_changelog_not_exists(self, temp_dir: Path) -> None:
        """Test reading non-existent changelog returns header."""
        changelog_path = temp_dir / "CHANGELOG.md"

        result = read_changelog(changelog_path)

        assert result == CHANGELOG_HEADER


class TestUpdateChangelog:
    """Tests for update_changelog function."""

    def test_update_changelog_new_file(self, temp_dir: Path) -> None:
        """Test updating non-existent changelog creates it."""
        changelog_path = temp_dir / "CHANGELOG.md"
        entries = [
            ChangelogEntry(
                date=datetime.now(),
                change_type=ChangeType.ADDED,
                rule_name="Test_Rule",
                description="Test",
                certificate_serial="abc",
            ),
        ]

        result_path = update_changelog(entries, changelog_path)

        assert result_path.exists()
        content = result_path.read_text()
        assert "# Changelog" in content
        assert "Test_Rule" in content

    def test_update_changelog_existing_file(self, temp_dir: Path) -> None:
        """Test updating existing changelog prepends new entries."""
        changelog_path = temp_dir / "CHANGELOG.md"
        changelog_path.write_text(
            CHANGELOG_HEADER + "## [2025.12.01] - 2025-12-01\n\n### Added\n- Old_Rule\n"
        )

        entries = [
            ChangelogEntry(
                date=datetime.now(),
                change_type=ChangeType.ADDED,
                rule_name="New_Rule",
                description="New",
                certificate_serial="xyz",
            ),
        ]

        update_changelog(entries, changelog_path)
        content = changelog_path.read_text()

        # New entry should come before old entry
        new_pos = content.find("New_Rule")
        old_pos = content.find("Old_Rule")
        assert new_pos < old_pos

    def test_update_changelog_empty_entries(self, temp_dir: Path) -> None:
        """Test that empty entries don't modify changelog."""
        changelog_path = temp_dir / "CHANGELOG.md"

        result_path = update_changelog([], changelog_path)

        assert result_path == changelog_path


class TestGenerateReleaseNotes:
    """Tests for generate_release_notes function."""

    def test_generate_release_notes_basic(
        self, temp_dir: Path, sample_records: list[CertificateRecord]
    ) -> None:
        """Test generating release notes."""
        output_path = temp_dir / "RELEASE_NOTES.md"

        result_path = generate_release_notes(
            added=sample_records[:2],
            modified=[sample_records[2]],
            removed=[],
            output_path=output_path,
        )

        assert result_path.exists()
        content = result_path.read_text()

        assert "## Summary" in content
        assert "**New Rules**: 2" in content
        assert "**Updated Rules**: 1" in content
        assert "## New Rules" in content
        assert "## Updated Rules" in content

    def test_generate_release_notes_many_rules(self, temp_dir: Path) -> None:
        """Test that release notes truncate long lists."""
        records = [
            CertificateRecord(hash=f"hash{i}", cert_serial=f"serial{i}")
            for i in range(30)
        ]
        output_path = temp_dir / "RELEASE_NOTES.md"

        generate_release_notes(
            added=records,
            modified=[],
            removed=[],
            output_path=output_path,
        )

        content = output_path.read_text()
        assert "... and 10 more" in content


class TestDetectChanges:
    """Tests for detect_changes function."""

    def test_detect_changes_all_new(self) -> None:
        """Test detecting all new records."""
        old_records: list[CertificateRecord] = []
        new_records = [
            CertificateRecord(hash="hash1", cert_serial="serial1"),
            CertificateRecord(hash="hash2", cert_serial="serial2"),
        ]

        entries = detect_changes(old_records, new_records)

        assert len(entries) == 2
        assert all(e.change_type == ChangeType.ADDED for e in entries)

    def test_detect_changes_mixed(self) -> None:
        """Test detecting mixed changes."""
        old_records = [
            CertificateRecord(hash="hash1", cert_serial="serial1"),
            CertificateRecord(
                hash="hash2", cert_serial="serial2", malware_name="OldName"
            ),
        ]
        new_records = [
            CertificateRecord(
                hash="hash2", cert_serial="serial2", malware_name="NewName"
            ),
            CertificateRecord(hash="hash3", cert_serial="serial3"),
        ]

        entries = detect_changes(old_records, new_records)

        added = [e for e in entries if e.change_type == ChangeType.ADDED]
        modified = [e for e in entries if e.change_type == ChangeType.MODIFIED]
        removed = [e for e in entries if e.change_type == ChangeType.REMOVED]

        assert len(added) == 1
        assert len(modified) == 1
        assert len(removed) == 1

