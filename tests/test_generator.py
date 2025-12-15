"""Tests for the generator module."""

from pathlib import Path

from cert_graveyard_yara.generator import (
    combine_rules,
    create_zip_archive,
    escape_yara_string,
    format_serial_number,
    generate_all_rules,
    generate_rule_content,
    generate_rule_filename,
    generate_rule_name,
    generate_single_rule,
    sanitize_name,
)
from cert_graveyard_yara.models import CertificateRecord


class TestSanitizeName:
    """Tests for sanitize_name function."""

    def test_sanitize_name_basic(self) -> None:
        """Test basic name sanitization."""
        result = sanitize_name("Emotet")
        assert result == "Emotet"

    def test_sanitize_name_with_spaces(self) -> None:
        """Test sanitization of names with spaces."""
        result = sanitize_name("Evil Corp Malware")
        assert result == "Evil_Corp_Malware"

    def test_sanitize_name_with_special_chars(self) -> None:
        """Test sanitization of names with special characters."""
        result = sanitize_name("Test@#$%Malware!")
        assert result == "Test_Malware"

    def test_sanitize_name_collapse_underscores(self) -> None:
        """Test that multiple underscores are collapsed."""
        result = sanitize_name("Test___Multiple___Underscores")
        assert result == "Test_Multiple_Underscores"

    def test_sanitize_name_strip_leading_trailing(self) -> None:
        """Test that leading/trailing underscores are stripped."""
        result = sanitize_name("___Test___")
        assert result == "Test"

    def test_sanitize_name_empty_string(self) -> None:
        """Test handling of empty string."""
        result = sanitize_name("", "Default")
        assert result == "Default"

    def test_sanitize_name_nan(self) -> None:
        """Test handling of NaN value."""
        result = sanitize_name("NaN", "Default", 5)
        assert result == "Default_5"

    def test_sanitize_name_with_index(self) -> None:
        """Test that index is appended when needed."""
        result = sanitize_name("", "Unknown", 42)
        assert result == "Unknown_42"


class TestFormatSerialNumber:
    """Tests for format_serial_number function."""

    def test_format_serial_basic(self) -> None:
        """Test basic serial formatting."""
        result = format_serial_number("0a1b2c3d")
        assert result == "0a:1b:2c:3d"

    def test_format_serial_uppercase(self) -> None:
        """Test that uppercase is converted to lowercase."""
        result = format_serial_number("0A1B2C3D")
        assert result == "0a:1b:2c:3d"

    def test_format_serial_already_formatted(self) -> None:
        """Test handling of already formatted serial."""
        result = format_serial_number("0a:1b:2c:3d")
        assert result == "0a:1b:2c:3d"

    def test_format_serial_empty(self) -> None:
        """Test handling of empty serial."""
        result = format_serial_number("")
        assert result == ""

    def test_format_serial_nan(self) -> None:
        """Test handling of NaN value."""
        result = format_serial_number("NaN")
        assert result == ""

    def test_format_serial_odd_length(self) -> None:
        """Test handling of odd-length serial."""
        result = format_serial_number("abc")
        assert result == "ab:c"


class TestEscapeYaraString:
    """Tests for escape_yara_string function."""

    def test_escape_quotes(self) -> None:
        """Test escaping of double quotes."""
        result = escape_yara_string('Test "quoted" string')
        assert result == 'Test \\"quoted\\" string'

    def test_escape_backslashes(self) -> None:
        """Test escaping of backslashes."""
        result = escape_yara_string("Path\\to\\file")
        assert result == "Path\\\\to\\\\file"

    def test_escape_both(self) -> None:
        """Test escaping of both quotes and backslashes."""
        result = escape_yara_string('"C:\\Windows"')
        assert result == '\\"C:\\\\Windows\\"'

    def test_escape_empty(self) -> None:
        """Test handling of empty string."""
        result = escape_yara_string("")
        assert result == ""


class TestGenerateRuleContent:
    """Tests for generate_rule_content function."""

    def test_generate_rule_content_basic(self, sample_record: CertificateRecord) -> None:
        """Test basic rule content generation."""
        content = generate_rule_content(sample_record)

        assert 'import "pe"' in content
        assert "MAL_Compromised_Cert_Emotet_DigiCert" in content
        assert "Emotet" in content
        assert "DigiCert" in content
        assert "0a:1b:2c:3d:4e:5f:6a:7b:8c:9d" in content
        assert "uint16(0) == 0x5a4d" in content

    def test_generate_rule_content_escapes_special_chars(self) -> None:
        """Test that special characters are escaped."""
        record = CertificateRecord(
            hash="test_hash",
            cert_serial="abc123",
            malware_name='Test "Malware"',
            cert_issuer='CN=Test\\Issuer',
        )
        content = generate_rule_content(record)

        # Check that quotes are escaped in metadata
        assert '\\"' in content or "Test" in content


class TestGenerateRuleFilename:
    """Tests for generate_rule_filename function."""

    def test_generate_rule_filename_basic(self, sample_record: CertificateRecord) -> None:
        """Test basic filename generation."""
        filename = generate_rule_filename(sample_record)

        assert filename.startswith("rule_MAL_Compromised_Cert_")
        assert filename.endswith(".yara")
        assert "Emotet" in filename
        assert "DigiCert" in filename


class TestGenerateRuleName:
    """Tests for generate_rule_name function."""

    def test_generate_rule_name_basic(self, sample_record: CertificateRecord) -> None:
        """Test basic rule name generation."""
        name = generate_rule_name(sample_record)

        assert name.startswith("MAL_Compromised_Cert_")
        assert "Emotet" in name
        assert "DigiCert" in name


class TestGenerateSingleRule:
    """Tests for generate_single_rule function."""

    def test_generate_single_rule_success(
        self, temp_dir: Path, sample_record: CertificateRecord
    ) -> None:
        """Test successful single rule generation."""
        result = generate_single_rule(sample_record, temp_dir)

        assert result.success is True
        assert result.rule_path.exists()
        assert result.rule_path.suffix == ".yara"
        assert result.certificate_serial == sample_record.cert_serial

        # Verify file content
        content = result.rule_path.read_text()
        assert 'import "pe"' in content
        assert "Emotet" in content


class TestGenerateAllRules:
    """Tests for generate_all_rules function."""

    def test_generate_all_rules_success(
        self, temp_dir: Path, sample_records: list[CertificateRecord]
    ) -> None:
        """Test generating multiple rules."""
        results = generate_all_rules(sample_records, temp_dir)

        assert len(results) == 3
        assert all(r.success for r in results)

        # Check files exist
        yara_files = list(temp_dir.glob("*.yara"))
        assert len(yara_files) == 3


class TestCombineRules:
    """Tests for combine_rules function."""

    def test_combine_rules_success(
        self, temp_dir: Path, sample_records: list[CertificateRecord]
    ) -> None:
        """Test combining multiple rules into one file."""
        individual_dir = temp_dir / "individual"
        combined_dir = temp_dir / "combined"

        # Generate individual rules first
        generate_all_rules(sample_records, individual_dir)

        # Combine them
        combined_path = combine_rules(individual_dir, combined_dir)

        assert combined_path.exists()
        content = combined_path.read_text()

        # Should have only one import statement
        assert content.count('import "pe"') == 1

        # Should have all rules
        assert "Malware1" in content
        assert "Malware2" in content
        assert "Malware3" in content

    def test_combine_rules_empty_dir(self, temp_dir: Path) -> None:
        """Test combining with empty directory."""
        individual_dir = temp_dir / "empty"
        individual_dir.mkdir()
        combined_dir = temp_dir / "combined"

        combined_path = combine_rules(individual_dir, combined_dir)

        assert combined_path.exists()
        content = combined_path.read_text()
        assert "No rules found" in content


class TestCreateZipArchive:
    """Tests for create_zip_archive function."""

    def test_create_zip_archive_success(
        self, temp_dir: Path, sample_records: list[CertificateRecord]
    ) -> None:
        """Test creating ZIP archive of rules."""
        individual_dir = temp_dir / "individual"
        output_dir = temp_dir / "output"

        # Generate rules first
        generate_all_rules(sample_records, individual_dir)

        # Create archive
        zip_path = create_zip_archive(individual_dir, output_dir)

        assert zip_path.exists()
        assert zip_path.suffix == ".zip"

        # Verify ZIP contents
        import zipfile

        with zipfile.ZipFile(zip_path, "r") as zf:
            names = zf.namelist()
            assert len(names) == 3
            assert all(name.endswith(".yara") for name in names)

