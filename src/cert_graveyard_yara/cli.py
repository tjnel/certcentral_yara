"""Command-line interface for CertGraveyard YARA Generator."""

import logging
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from . import __version__
from .changelog import (
    detect_changes,
    generate_release_notes,
    update_changelog,
)
from .downloader import (
    DEFAULT_CSV_FILENAME,
    DEFAULT_DATA_DIR,
    DEFAULT_HASH_FILENAME,
    calculate_hash,
    download_csv_sync,
    get_stored_hash,
    has_csv_changed,
    save_hash,
)
from .generator import (
    DEFAULT_COMBINED_DIR,
    DEFAULT_INDIVIDUAL_DIR,
    combine_rules,
    create_zip_archive,
    generate_all_rules,
)
from .parser import parse_csv
from .validator import (
    ValidationEngine,
    format_validation_errors,
    get_validation_summary,
    validate_all_rules,
)

# Create Typer app
app = typer.Typer(
    name="cert-central-yara",
    help="Automated YARA rule generation from CertGraveyard compromised certificate database.",
    add_completion=False,
)

console = Console()


def setup_logging(verbose: bool = False) -> None:
    """Configure logging with Rich handler."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(f"cert-central-yara version {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option("--version", "-v", callback=version_callback, is_eager=True),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-V", help="Enable verbose logging"),
    ] = False,
) -> None:
    """CertGraveyard YARA Rules Generator CLI."""
    setup_logging(verbose)


@app.command()
def download(
    url: Annotated[
        str | None,
        typer.Option("--url", "-u", help="CSV download URL"),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output file path"),
    ] = None,
) -> None:
    """Download the CertGraveyard CSV file."""
    from .downloader import CERTGRAVEYARD_CSV_URL

    url = url or CERTGRAVEYARD_CSV_URL
    output = output or (DEFAULT_DATA_DIR / DEFAULT_CSV_FILENAME)

    console.print(f"[blue]Downloading CSV from {url}...[/blue]")

    try:
        result_path = download_csv_sync(url=url, output_path=output)
        console.print(f"[green]✓ Downloaded to {result_path}[/green]")
    except Exception as e:
        console.print(f"[red]✗ Download failed: {e}[/red]")
        raise typer.Exit(1) from None


@app.command("check-changed")
def check_changed(
    csv_path: Annotated[
        Path | None,
        typer.Option("--csv", "-c", help="Path to CSV file"),
    ] = None,
) -> None:
    """Check if the CSV file has changed since last run."""
    csv_path = csv_path or (DEFAULT_DATA_DIR / DEFAULT_CSV_FILENAME)
    hash_file = DEFAULT_DATA_DIR / DEFAULT_HASH_FILENAME

    if not csv_path.exists():
        console.print(f"[red]✗ CSV file not found: {csv_path}[/red]")
        raise typer.Exit(1)

    new_hash = calculate_hash(csv_path)
    old_hash = get_stored_hash(hash_file)

    if has_csv_changed(new_hash, hash_file):
        console.print("[green]✓ CSV has changed[/green]")
        if old_hash:
            console.print(f"  Old hash: {old_hash[:16]}...")
        console.print(f"  New hash: {new_hash[:16]}...")
        raise typer.Exit(0)
    else:
        console.print("[yellow]○ CSV has not changed[/yellow]")
        raise typer.Exit(1)


@app.command()
def generate(
    csv_path: Annotated[
        Path | None,
        typer.Option("--csv", "-c", help="Path to CSV file"),
    ] = None,
    output_dir: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output directory for rules"),
    ] = None,
    save_csv_hash: Annotated[
        bool,
        typer.Option("--save-hash/--no-save-hash", help="Save CSV hash after generation"),
    ] = True,
) -> None:
    """Generate YARA rules from the CSV file."""
    csv_path = csv_path or (DEFAULT_DATA_DIR / DEFAULT_CSV_FILENAME)
    output_dir = output_dir or DEFAULT_INDIVIDUAL_DIR

    if not csv_path.exists():
        console.print(f"[red]✗ CSV file not found: {csv_path}[/red]")
        raise typer.Exit(1)

    console.print(f"[blue]Parsing CSV: {csv_path}[/blue]")

    try:
        records = parse_csv(csv_path)
        console.print(f"[green]✓ Parsed {len(records)} certificate records[/green]")
    except Exception as e:
        console.print(f"[red]✗ Parse failed: {e}[/red]")
        raise typer.Exit(1) from None

    console.print(f"[blue]Generating YARA rules in {output_dir}...[/blue]")

    try:
        results = generate_all_rules(records, output_dir)
        success_count = sum(1 for r in results if r.success)
        fail_count = len(results) - success_count

        console.print(f"[green]✓ Generated {success_count} rules[/green]")
        if fail_count > 0:
            console.print(f"[yellow]⚠ {fail_count} rules failed to generate[/yellow]")
    except Exception as e:
        console.print(f"[red]✗ Generation failed: {e}[/red]")
        raise typer.Exit(1) from None

    if save_csv_hash:
        hash_value = calculate_hash(csv_path)
        save_hash(hash_value)
        console.print("[dim]Saved CSV hash[/dim]")


@app.command()
def validate(
    rules_dir: Annotated[
        Path | None,
        typer.Option("--dir", "-d", help="Directory containing YARA rules"),
    ] = None,
    engine: Annotated[
        ValidationEngine,
        typer.Option("--engine", "-e", help="Validation engine to use"),
    ] = ValidationEngine.YARA,
) -> None:
    """Validate YARA rules using YARA or YARA-X."""
    rules_dir = rules_dir or DEFAULT_INDIVIDUAL_DIR

    if not rules_dir.exists():
        console.print(f"[red]✗ Rules directory not found: {rules_dir}[/red]")
        raise typer.Exit(1)

    console.print(f"[blue]Validating rules in {rules_dir} with {engine.value}...[/blue]")

    results = validate_all_rules(rules_dir, engine)

    if not results:
        console.print("[yellow]○ No rules found to validate[/yellow]")
        raise typer.Exit(0)

    summary = get_validation_summary(results)

    # Display summary table
    table = Table(title="Validation Summary")
    table.add_column("Engine", style="cyan")
    table.add_column("Valid", style="green")
    table.add_column("Invalid", style="red")

    if engine in (ValidationEngine.YARA, ValidationEngine.BOTH):
        table.add_row("YARA", str(summary["yara_valid"]), str(summary["yara_invalid"]))
    if engine in (ValidationEngine.YARA_X, ValidationEngine.BOTH):
        table.add_row("YARA-X", str(summary["yara_x_valid"]), str(summary["yara_x_invalid"]))

    console.print(table)

    # Show errors if any
    invalid_results = [r for r in results if not r.is_valid]
    if invalid_results:
        console.print("\n[red]Validation Errors:[/red]")
        console.print(format_validation_errors(results, max_errors=10))
        raise typer.Exit(1)
    else:
        console.print("[green]✓ All rules validated successfully[/green]")


@app.command()
def changelog(
    csv_path: Annotated[
        Path | None,
        typer.Option("--csv", "-c", help="Path to current CSV file"),
    ] = None,
    previous_csv: Annotated[
        Path | None,
        typer.Option("--previous", "-p", help="Path to previous CSV file for comparison"),
    ] = None,
) -> None:
    """Update the changelog with detected changes."""
    csv_path = csv_path or (DEFAULT_DATA_DIR / DEFAULT_CSV_FILENAME)

    if not csv_path.exists():
        console.print(f"[red]✗ CSV file not found: {csv_path}[/red]")
        raise typer.Exit(1)

    console.print("[blue]Parsing current CSV...[/blue]")
    new_records = parse_csv(csv_path)

    # If no previous CSV provided, just create entries for all current records as "added"
    if previous_csv and previous_csv.exists():
        console.print("[blue]Parsing previous CSV...[/blue]")
        old_records = parse_csv(previous_csv)
    else:
        console.print("[yellow]No previous CSV for comparison - treating all as new[/yellow]")
        old_records = []

    entries = detect_changes(old_records, new_records)

    if not entries:
        console.print("[yellow]○ No changes detected[/yellow]")
        raise typer.Exit(0)

    update_changelog(entries)
    console.print(f"[green]✓ Updated CHANGELOG.md with {len(entries)} entries[/green]")


@app.command()
def combine(
    input_dir: Annotated[
        Path | None,
        typer.Option("--input", "-i", help="Directory containing individual rules"),
    ] = None,
    output_dir: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output directory for combined file"),
    ] = None,
) -> None:
    """Combine all individual YARA rules into a single file."""
    input_dir = input_dir or DEFAULT_INDIVIDUAL_DIR
    output_dir = output_dir or DEFAULT_COMBINED_DIR

    if not input_dir.exists():
        console.print(f"[red]✗ Input directory not found: {input_dir}[/red]")
        raise typer.Exit(1)

    console.print(f"[blue]Combining rules from {input_dir}...[/blue]")

    try:
        output_path = combine_rules(input_dir, output_dir)
        console.print(f"[green]✓ Created combined file: {output_path}[/green]")
    except Exception as e:
        console.print(f"[red]✗ Combine failed: {e}[/red]")
        raise typer.Exit(1) from None


@app.command()
def package(
    input_dir: Annotated[
        Path | None,
        typer.Option("--input", "-i", help="Directory containing individual rules"),
    ] = None,
    output_file: Annotated[
        str | None,
        typer.Option("--output", "-o", help="Output ZIP filename"),
    ] = None,
) -> None:
    """Create a ZIP archive of all individual YARA rules."""
    input_dir = input_dir or DEFAULT_INDIVIDUAL_DIR

    if not input_dir.exists():
        console.print(f"[red]✗ Input directory not found: {input_dir}[/red]")
        raise typer.Exit(1)

    console.print(f"[blue]Creating ZIP archive from {input_dir}...[/blue]")

    try:
        output_filename = output_file or "cert_graveyard_yara_rules.zip"
        zip_path = create_zip_archive(input_dir, output_filename=output_filename)
        console.print(f"[green]✓ Created ZIP archive: {zip_path}[/green]")
    except Exception as e:
        console.print(f"[red]✗ Package failed: {e}[/red]")
        raise typer.Exit(1) from None


@app.command()
def run(
    all_steps: Annotated[
        bool,
        typer.Option("--all", "-a", help="Run all pipeline steps"),
    ] = False,
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Force update even if CSV unchanged"),
    ] = False,
) -> None:
    """Run the full YARA rule generation pipeline."""
    csv_path = DEFAULT_DATA_DIR / DEFAULT_CSV_FILENAME
    hash_file = DEFAULT_DATA_DIR / DEFAULT_HASH_FILENAME

    # Step 1: Download
    console.print("\n[bold]Step 1: Download CSV[/bold]")
    try:
        download_csv_sync(output_path=csv_path)
        console.print("[green]✓ Download complete[/green]")
    except Exception as e:
        console.print(f"[red]✗ Download failed: {e}[/red]")
        raise typer.Exit(1) from None

    # Step 2: Check for changes
    console.print("\n[bold]Step 2: Check for changes[/bold]")
    new_hash = calculate_hash(csv_path)
    changed = has_csv_changed(new_hash, hash_file) or force

    if not changed and not all_steps:
        console.print("[yellow]○ No changes detected - skipping generation[/yellow]")
        raise typer.Exit(0)

    if force:
        console.print("[yellow]⚠ Force mode enabled[/yellow]")

    # Step 3: Parse and generate
    console.print("\n[bold]Step 3: Generate YARA rules[/bold]")
    records = parse_csv(csv_path)
    console.print(f"[dim]Parsed {len(records)} records[/dim]")

    results = generate_all_rules(records)
    success_count = sum(1 for r in results if r.success)
    console.print(f"[green]✓ Generated {success_count} rules[/green]")

    # Step 4: Validate
    console.print("\n[bold]Step 4: Validate rules[/bold]")
    validation_results = validate_all_rules(DEFAULT_INDIVIDUAL_DIR, ValidationEngine.YARA)
    invalid = [r for r in validation_results if not r.is_valid]

    if invalid:
        console.print(f"[red]✗ {len(invalid)} rules failed validation[/red]")
        console.print(format_validation_errors(validation_results, max_errors=5))
        raise typer.Exit(1)
    else:
        console.print("[green]✓ All rules validated[/green]")

    # Step 5: Save hash
    save_hash(new_hash, hash_file)
    console.print("[dim]Saved CSV hash[/dim]")

    # Step 6: Combine and package (if --all)
    if all_steps:
        console.print("\n[bold]Step 5: Create release artifacts[/bold]")
        combine_rules()
        create_zip_archive()
        generate_release_notes(records, [], [])
        console.print("[green]✓ Release artifacts created[/green]")

    console.print("\n[bold green]Pipeline complete![/bold green]")


if __name__ == "__main__":
    app()

