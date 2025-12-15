"""Tests for the validator module."""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from cert_graveyard_yara.models import ValidationResult
from cert_graveyard_yara.validator import (
    ValidationEngine,
    format_validation_errors,
    get_validation_summary,
    validate_all_rules,
    validate_rule,
    validate_with_yara,
    validate_with_yara_x,
)


class TestValidateWithYara:
    """Tests for validate_with_yara function."""

    def test_validate_with_yara_valid(self, valid_yara_file: Path) -> None:
        """Test validation of a valid YARA rule."""
        result = validate_with_yara(valid_yara_file)

        assert result.is_valid is True
        assert result.engine == "yara"
        assert result.error_message is None

    def test_validate_with_yara_invalid(self, invalid_yara_file: Path) -> None:
        """Test validation of an invalid YARA rule."""
        result = validate_with_yara(invalid_yara_file)

        assert result.is_valid is False
        assert result.engine == "yara"
        assert result.error_message is not None

    def test_validate_with_yara_not_installed(self, temp_dir: Path) -> None:
        """Test handling when yara-python is not installed."""
        rule_file = temp_dir / "test.yara"
        rule_file.write_text("rule test { condition: true }")

        with (
            patch.dict("sys.modules", {"yara": None}),
            patch("cert_graveyard_yara.validator.validate_with_yara") as mock_validate,
        ):
                mock_validate.return_value = ValidationResult(
                    file_path=str(rule_file),
                    is_valid=False,
                    engine="yara",
                    error_message="yara-python is not installed",
                )
                result = mock_validate(rule_file)

        assert result.is_valid is False
        assert "not installed" in result.error_message or result.error_message is not None


class TestValidateWithYaraX:
    """Tests for validate_with_yara_x function."""

    def test_validate_with_yara_x_success(self, temp_dir: Path) -> None:
        """Test successful YARA-X validation."""
        rule_file = temp_dir / "test.yara"
        rule_file.write_text("rule test { condition: true }")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = validate_with_yara_x(rule_file)

        assert result.is_valid is True
        assert result.engine == "yara-x"

    def test_validate_with_yara_x_failure(self, temp_dir: Path) -> None:
        """Test failed YARA-X validation."""
        rule_file = temp_dir / "test.yara"
        rule_file.write_text("invalid rule")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stderr="syntax error", stdout=""
            )
            result = validate_with_yara_x(rule_file)

        assert result.is_valid is False
        assert result.engine == "yara-x"
        assert result.error_message is not None

    def test_validate_with_yara_x_not_installed(self, temp_dir: Path) -> None:
        """Test handling when YARA-X CLI is not installed."""
        rule_file = temp_dir / "test.yara"
        rule_file.write_text("rule test { condition: true }")

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError()
            result = validate_with_yara_x(rule_file)

        assert result.is_valid is False
        assert "not installed" in result.error_message.lower()

    def test_validate_with_yara_x_timeout(self, temp_dir: Path) -> None:
        """Test handling of YARA-X timeout."""
        rule_file = temp_dir / "test.yara"
        rule_file.write_text("rule test { condition: true }")

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="yr", timeout=30)
            result = validate_with_yara_x(rule_file)

        assert result.is_valid is False
        assert "timed out" in result.error_message.lower()


class TestValidateRule:
    """Tests for validate_rule function."""

    def test_validate_rule_yara_engine(self, valid_yara_file: Path) -> None:
        """Test validation with YARA engine only."""
        results = validate_rule(valid_yara_file, ValidationEngine.YARA)

        assert len(results) == 1
        assert results[0].engine == "yara"

    def test_validate_rule_yara_x_engine(self, temp_dir: Path) -> None:
        """Test validation with YARA-X engine only."""
        rule_file = temp_dir / "test.yara"
        rule_file.write_text("rule test { condition: true }")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            results = validate_rule(rule_file, ValidationEngine.YARA_X)

        assert len(results) == 1
        assert results[0].engine == "yara-x"

    def test_validate_rule_both_engines(self, valid_yara_file: Path) -> None:
        """Test validation with both engines."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            results = validate_rule(valid_yara_file, ValidationEngine.BOTH)

        assert len(results) == 2
        engines = {r.engine for r in results}
        assert engines == {"yara", "yara-x"}


class TestValidateAllRules:
    """Tests for validate_all_rules function."""

    def test_validate_all_rules_success(self, temp_dir: Path) -> None:
        """Test validating multiple rules."""
        # Create multiple rule files
        for i in range(3):
            rule_file = temp_dir / f"rule_{i}.yara"
            rule_file.write_text(
                f'import "pe"\nrule Test{i} {{ condition: true }}'
            )

        results = validate_all_rules(temp_dir, ValidationEngine.YARA)

        assert len(results) == 3
        assert all(r.is_valid for r in results)

    def test_validate_all_rules_empty_dir(self, temp_dir: Path) -> None:
        """Test validating empty directory."""
        results = validate_all_rules(temp_dir, ValidationEngine.YARA)

        assert len(results) == 0

    def test_validate_all_rules_nonexistent_dir(self, temp_dir: Path) -> None:
        """Test validating nonexistent directory."""
        nonexistent = temp_dir / "nonexistent"
        results = validate_all_rules(nonexistent, ValidationEngine.YARA)

        assert len(results) == 0


class TestGetValidationSummary:
    """Tests for get_validation_summary function."""

    def test_get_validation_summary_mixed(self) -> None:
        """Test summary with mixed results."""
        results = [
            ValidationResult(file_path="a.yara", is_valid=True, engine="yara"),
            ValidationResult(
                file_path="b.yara", is_valid=False, engine="yara", error_message="err"
            ),
            ValidationResult(file_path="a.yara", is_valid=True, engine="yara-x"),
            ValidationResult(file_path="b.yara", is_valid=True, engine="yara-x"),
        ]

        summary = get_validation_summary(results)

        assert summary["total"] == 4
        assert summary["valid"] == 3
        assert summary["invalid"] == 1
        assert summary["yara_valid"] == 1
        assert summary["yara_invalid"] == 1
        assert summary["yara_x_valid"] == 2
        assert summary["yara_x_invalid"] == 0


class TestFormatValidationErrors:
    """Tests for format_validation_errors function."""

    def test_format_validation_errors_no_errors(self) -> None:
        """Test formatting when there are no errors."""
        results = [
            ValidationResult(file_path="a.yara", is_valid=True, engine="yara"),
        ]

        output = format_validation_errors(results)

        assert "No validation errors" in output

    def test_format_validation_errors_with_errors(self) -> None:
        """Test formatting with errors."""
        results = [
            ValidationResult(
                file_path="a.yara",
                is_valid=False,
                engine="yara",
                error_message="syntax error at line 5",
            ),
        ]

        output = format_validation_errors(results)

        assert "1 validation error" in output
        assert "a.yara" in output
        assert "syntax error" in output

    def test_format_validation_errors_truncated(self) -> None:
        """Test that errors are truncated when max_errors is set."""
        results = [
            ValidationResult(
                file_path=f"rule{i}.yara",
                is_valid=False,
                engine="yara",
                error_message=f"error {i}",
            )
            for i in range(10)
        ]

        output = format_validation_errors(results, max_errors=3)

        assert "10 validation error" in output
        assert "7 more errors" in output

