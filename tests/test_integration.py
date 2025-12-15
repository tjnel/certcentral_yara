"""Integration tests for the full pipeline."""

from pathlib import Path

from cert_graveyard_yara.changelog import detect_changes, update_changelog
from cert_graveyard_yara.downloader import calculate_hash, has_csv_changed, save_hash
from cert_graveyard_yara.generator import combine_rules, create_zip_archive, generate_all_rules
from cert_graveyard_yara.models import CertificateRecord
from cert_graveyard_yara.parser import parse_csv
from cert_graveyard_yara.validator import ValidationEngine, validate_all_rules


class TestFullPipeline:
    """Integration tests for the complete pipeline."""

    def test_full_pipeline_new_csv(
        self, temp_dir: Path, sample_csv_content: str
    ) -> None:
        """Test full pipeline with a new CSV file."""
        # Setup directories
        data_dir = temp_dir / "data"
        rules_dir = temp_dir / "rules"
        individual_dir = rules_dir / "individual"
        combined_dir = rules_dir / "combined"

        data_dir.mkdir(parents=True)

        # Create CSV file
        csv_path = data_dir / "test.csv"
        csv_path.write_text(sample_csv_content)

        # Step 1: Check for changes (no previous hash)
        csv_hash = calculate_hash(csv_path)
        hash_file = data_dir / ".csv_hash"
        assert has_csv_changed(csv_hash, hash_file) is True

        # Step 2: Parse CSV
        records = parse_csv(csv_path)
        assert len(records) == 2

        # Step 3: Generate rules
        results = generate_all_rules(records, individual_dir)
        assert all(r.success for r in results)
        assert len(list(individual_dir.glob("*.yara"))) == 2

        # Step 4: Validate rules
        validation_results = validate_all_rules(individual_dir, ValidationEngine.YARA)
        assert all(r.is_valid for r in validation_results)

        # Step 5: Save hash
        save_hash(csv_hash, hash_file)
        assert hash_file.exists()

        # Step 6: Combine rules
        combined_path = combine_rules(individual_dir, combined_dir)
        assert combined_path.exists()

        # Step 7: Create ZIP
        zip_path = create_zip_archive(individual_dir, rules_dir)
        assert zip_path.exists()

    def test_full_pipeline_unchanged_csv(
        self, temp_dir: Path, sample_csv_content: str
    ) -> None:
        """Test pipeline behavior when CSV hasn't changed."""
        data_dir = temp_dir / "data"
        data_dir.mkdir(parents=True)

        # Create CSV and save its hash
        csv_path = data_dir / "test.csv"
        csv_path.write_text(sample_csv_content)

        csv_hash = calculate_hash(csv_path)
        hash_file = data_dir / ".csv_hash"
        save_hash(csv_hash, hash_file)

        # Check for changes - should return False
        assert has_csv_changed(csv_hash, hash_file) is False

    def test_full_pipeline_modified_csv(
        self, temp_dir: Path, sample_csv_content: str
    ) -> None:
        """Test pipeline when CSV has been modified."""
        data_dir = temp_dir / "data"
        data_dir.mkdir(parents=True)

        # Create initial CSV and save hash
        csv_path = data_dir / "test.csv"
        csv_path.write_text(sample_csv_content)

        old_hash = calculate_hash(csv_path)
        hash_file = data_dir / ".csv_hash"
        save_hash(old_hash, hash_file)

        # Modify CSV
        new_content = sample_csv_content + (
            "newHash123,NewMalware,Ransomware,Notes,Signer,NewIssuer,"
            "Full Issuer,newserial123,thumb,2024-03-01,2025-03-01,"
            "DE,Berlin,Berlin,new@test.com,99999\n"
        )
        csv_path.write_text(new_content)

        # Check for changes
        new_hash = calculate_hash(csv_path)
        assert has_csv_changed(new_hash, hash_file) is True

        # Parse and check new records
        records = parse_csv(csv_path)
        assert len(records) == 3


class TestChangelogIntegration:
    """Integration tests for changelog functionality."""

    def test_changelog_with_record_changes(self, temp_dir: Path) -> None:
        """Test changelog updates when records change."""
        changelog_path = temp_dir / "CHANGELOG.md"

        old_records = [
            CertificateRecord(hash="hash1", cert_serial="serial1", malware_name="Emotet"),
        ]
        new_records = [
            CertificateRecord(
                hash="hash1", cert_serial="serial1", malware_name="Emotet v2"
            ),  # Modified
            CertificateRecord(hash="hash2", cert_serial="serial2", malware_name="Qakbot"),  # Added
        ]

        # Detect changes
        entries = detect_changes(old_records, new_records)

        # Update changelog
        update_changelog(entries, changelog_path)

        # Verify changelog
        content = changelog_path.read_text()
        assert "### Added" in content
        assert "### Modified" in content
        assert "Qakbot" in content or "MAL_Compromised_Cert" in content


class TestValidationIntegration:
    """Integration tests for rule validation."""

    def test_generated_rules_valid_yara(
        self, temp_dir: Path, sample_records: list[CertificateRecord]
    ) -> None:
        """Test that all generated rules pass YARA validation."""
        rules_dir = temp_dir / "rules"

        # Generate rules
        generate_all_rules(sample_records, rules_dir)

        # Validate with YARA
        results = validate_all_rules(rules_dir, ValidationEngine.YARA)

        # All should be valid
        assert len(results) == len(sample_records)
        for result in results:
            assert result.is_valid, f"Rule failed validation: {result.error_message}"

    def test_combined_rules_valid_yara(
        self, temp_dir: Path, sample_records: list[CertificateRecord]
    ) -> None:
        """Test that combined rules file passes YARA validation."""
        individual_dir = temp_dir / "individual"
        combined_dir = temp_dir / "combined"

        # Generate and combine rules
        generate_all_rules(sample_records, individual_dir)
        combine_rules(individual_dir, combined_dir)

        # Validate combined file
        results = validate_all_rules(combined_dir, ValidationEngine.YARA)

        assert len(results) == 1
        assert results[0].is_valid, f"Combined rule failed: {results[0].error_message}"


class TestEdgeCases:
    """Integration tests for edge cases."""

    def test_special_characters_in_records(self, temp_dir: Path) -> None:
        """Test handling of special characters in certificate data."""
        records = [
            CertificateRecord(
                hash="hash_special",
                cert_serial="serial_special",
                malware_name='Malware "Quoted"',
                cert_issuer='CN=Test\\CA, O="Company, Inc."',
                signer="O'Malley's Corp",
            ),
        ]

        rules_dir = temp_dir / "rules"
        results = generate_all_rules(records, rules_dir)

        assert all(r.success for r in results)

        # Validate generated rule
        validation = validate_all_rules(rules_dir, ValidationEngine.YARA)
        assert all(v.is_valid for v in validation)

    def test_empty_optional_fields(self, temp_dir: Path) -> None:
        """Test handling of empty optional fields."""
        records = [
            CertificateRecord(
                hash="minimal_hash",
                cert_serial="minimal_serial",
                # All optional fields use defaults
            ),
        ]

        rules_dir = temp_dir / "rules"
        results = generate_all_rules(records, rules_dir)

        assert all(r.success for r in results)

        # Check rule content
        rule_file = list(rules_dir.glob("*.yara"))[0]
        content = rule_file.read_text()
        assert "Unknown" in content  # Default values should appear

    def test_very_long_serial_number(self, temp_dir: Path) -> None:
        """Test handling of very long serial numbers."""
        # Use a reasonable serial number length (real serials are typically 16-40 hex chars)
        long_serial = "a" * 40
        records = [
            CertificateRecord(
                hash="hash_long_serial",
                cert_serial=long_serial,
            ),
        ]

        rules_dir = temp_dir / "rules"
        results = generate_all_rules(records, rules_dir)

        assert all(r.success for r in results)

        # Verify the rule is valid
        validation = validate_all_rules(rules_dir, ValidationEngine.YARA)
        assert all(v.is_valid for v in validation)

