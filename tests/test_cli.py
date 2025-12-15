"""Tests for the CLI module."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from cert_graveyard_yara.cli import app

runner = CliRunner()


class TestCLI:
    """Tests for CLI commands."""

    def test_version(self) -> None:
        """Test --version flag."""
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "1.0.0" in result.stdout

    def test_download_file_not_found_url(self, temp_dir: Path) -> None:
        """Test download with invalid URL."""
        with patch("cert_graveyard_yara.cli.download_csv_sync") as mock_download:
            mock_download.side_effect = Exception("Connection failed")
            result = runner.invoke(
                app,
                ["download", "--output", str(temp_dir / "test.csv")],
            )
            assert result.exit_code == 1
            assert "failed" in result.stdout.lower()

    def test_check_changed_no_file(self, temp_dir: Path) -> None:
        """Test check-changed with missing CSV file."""
        result = runner.invoke(
            app,
            ["check-changed", "--csv", str(temp_dir / "nonexistent.csv")],
        )
        assert result.exit_code == 1
        assert "not found" in result.stdout.lower()

    def test_generate_no_file(self, temp_dir: Path) -> None:
        """Test generate with missing CSV file."""
        result = runner.invoke(
            app,
            ["generate", "--csv", str(temp_dir / "nonexistent.csv")],
        )
        assert result.exit_code == 1
        assert "not found" in result.stdout.lower()

    def test_generate_success(self, temp_dir: Path, sample_csv_content: str) -> None:
        """Test successful rule generation."""
        csv_path = temp_dir / "test.csv"
        csv_path.write_text(sample_csv_content)
        output_dir = temp_dir / "rules"

        result = runner.invoke(
            app,
            [
                "generate",
                "--csv", str(csv_path),
                "--output", str(output_dir),
                "--no-save-hash",
            ],
        )

        assert result.exit_code == 0
        assert "Generated" in result.stdout

    def test_validate_no_dir(self, temp_dir: Path) -> None:
        """Test validate with missing rules directory."""
        result = runner.invoke(
            app,
            ["validate", "--dir", str(temp_dir / "nonexistent")],
        )
        assert result.exit_code == 1
        assert "not found" in result.stdout.lower()

    def test_validate_success(self, temp_dir: Path, valid_yara_rule: str) -> None:
        """Test successful rule validation."""
        rules_dir = temp_dir / "rules"
        rules_dir.mkdir()
        rule_file = rules_dir / "test.yara"
        rule_file.write_text(valid_yara_rule)

        result = runner.invoke(
            app,
            ["validate", "--dir", str(rules_dir), "--engine", "yara"],
        )

        assert result.exit_code == 0
        assert "validated successfully" in result.stdout.lower() or "valid" in result.stdout.lower()

    def test_combine_no_dir(self, temp_dir: Path) -> None:
        """Test combine with missing input directory."""
        result = runner.invoke(
            app,
            ["combine", "--input", str(temp_dir / "nonexistent")],
        )
        assert result.exit_code == 1
        assert "not found" in result.stdout.lower()

    def test_package_no_dir(self, temp_dir: Path) -> None:
        """Test package with missing input directory."""
        result = runner.invoke(
            app,
            ["package", "--input", str(temp_dir / "nonexistent")],
        )
        assert result.exit_code == 1
        assert "not found" in result.stdout.lower()

    def test_changelog_no_file(self, temp_dir: Path) -> None:
        """Test changelog with missing CSV file."""
        result = runner.invoke(
            app,
            ["changelog", "--csv", str(temp_dir / "nonexistent.csv")],
        )
        assert result.exit_code == 1
        assert "not found" in result.stdout.lower()

