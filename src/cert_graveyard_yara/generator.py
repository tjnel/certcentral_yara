"""YARA rule generation module."""

import logging
import re
import zipfile
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, Template

from .models import CertificateRecord, GenerationResult

logger = logging.getLogger(__name__)

# Default paths
DEFAULT_RULES_DIR = Path("rules")
DEFAULT_INDIVIDUAL_DIR = DEFAULT_RULES_DIR / "individual"
DEFAULT_COMBINED_DIR = DEFAULT_RULES_DIR / "combined"
DEFAULT_TEMPLATES_DIR = Path("templates")

# YARA rule template as a string (fallback if file not found)
DEFAULT_YARA_TEMPLATE = """import "pe"

rule MAL_Compromised_Cert_{{ malware_name_safe }}_{{ issuer_short_safe }}_{{ serial_safe }} {
   meta:
      description         = "Detects {{ malware_name }} with compromised cert ({{ issuer_short }})"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "{{ valid_from }}"
      version             = "1.0"

      hash                = "{{ hash }}"
      malware             = "{{ malware_name }}"
      malware_type        = "{{ malware_type }}"
      malware_notes       = "{{ malware_notes }}"

      signer              = "{{ signer }}"
      cert_issuer_short   = "{{ issuer_short }}"
      cert_issuer         = "{{ issuer }}"
      cert_serial         = "{{ serial }}"
      cert_thumbprint     = "{{ thumbprint }}"
      cert_valid_from     = "{{ valid_from }}"
      cert_valid_to       = "{{ valid_to }}"

      country             = "{{ country }}"
      state               = "{{ state }}"
      locality            = "{{ locality }}"
      email               = "{{ email }}"
      rdn_serial_number   = "{{ rdn_serial }}"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "{{ issuer_escaped }}" and
         sig.serial == "{{ serial }}"
      )
}
"""


def sanitize_name(value: str, default: str = "Unknown", index: int = 0) -> str:
    """Sanitize a string for use in YARA rule names.

    Replaces non-alphanumeric characters with underscores, collapses
    multiple underscores, and strips leading/trailing underscores.

    Args:
        value: String to sanitize.
        default: Default value if input is empty.
        index: Index to append to default if needed.

    Returns:
        Sanitized string safe for YARA rule names.
    """
    if not value or value.strip() == "" or value == "NaN":
        return f"{default}_{index}" if index > 0 else default

    # Replace non-alphanumeric with underscore
    sanitized = re.sub(r"[^a-zA-Z0-9]", "_", value)
    # Collapse multiple underscores
    sanitized = re.sub(r"_{2,}", "_", sanitized)
    # Strip leading/trailing underscores
    sanitized = sanitized.strip("_")

    return sanitized if sanitized else f"{default}_{index}" if index > 0 else default


def format_serial_number(serial: str) -> str:
    """Format a serial number with colons and lowercase.

    Args:
        serial: Raw serial number string.

    Returns:
        Formatted serial number (e.g., "0a:1b:2c:3d").
    """
    if not serial or serial.strip() == "" or serial == "NaN":
        return ""

    # Remove any existing colons or spaces
    clean = serial.strip().lower().replace(":", "").replace(" ", "")

    # Add colons every two characters
    return ":".join(clean[i : i + 2] for i in range(0, len(clean), 2))


def escape_yara_string(value: str) -> str:
    """Escape a string for use in YARA string literals.

    Args:
        value: String to escape.

    Returns:
        Escaped string safe for YARA.
    """
    if not value:
        return ""

    # Escape backslashes first, then double quotes
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return escaped


def _get_template(templates_dir: Path | None = None) -> Template:
    """Get the Jinja2 template for YARA rules.

    Args:
        templates_dir: Directory containing template files.

    Returns:
        Jinja2 Template object.
    """
    if templates_dir is None:
        templates_dir = DEFAULT_TEMPLATES_DIR

    template_file = templates_dir / "yara_rule.template"

    if template_file.exists():
        env = Environment(loader=FileSystemLoader(templates_dir), autoescape=False)
        return env.get_template("yara_rule.template")

    # Fall back to default template string
    return Template(DEFAULT_YARA_TEMPLATE)


def generate_rule_content(
    record: CertificateRecord,
    index: int = 0,
    templates_dir: Path | None = None,
) -> str:
    """Generate YARA rule content for a certificate record.

    Args:
        record: Certificate record to generate rule for.
        index: Index for unique naming.
        templates_dir: Directory containing templates.

    Returns:
        Generated YARA rule content.
    """
    template = _get_template(templates_dir)

    # Format serial number
    formatted_serial = format_serial_number(record.cert_serial)

    # Prepare template context
    context = {
        # Safe names for rule identifier
        "malware_name_safe": sanitize_name(record.malware_name, "Unknown_Malware", index),
        "issuer_short_safe": sanitize_name(record.cert_issuer_short, "Unknown_Issuer", index),
        "serial_safe": sanitize_name(record.cert_serial, "Unknown_Serial", index),
        # Original values for metadata
        "hash": escape_yara_string(record.hash),
        "malware_name": escape_yara_string(record.malware_name),
        "malware_type": escape_yara_string(record.malware_type),
        "malware_notes": escape_yara_string(record.malware_notes),
        "signer": escape_yara_string(record.signer),
        "issuer_short": escape_yara_string(record.cert_issuer_short),
        "issuer": escape_yara_string(record.cert_issuer),
        "issuer_escaped": escape_yara_string(record.cert_issuer),
        "serial": formatted_serial,
        "thumbprint": escape_yara_string(record.cert_thumbprint),
        "valid_from": escape_yara_string(record.cert_valid_from),
        "valid_to": escape_yara_string(record.cert_valid_to),
        "country": escape_yara_string(record.country),
        "state": escape_yara_string(record.state),
        "locality": escape_yara_string(record.locality),
        "email": escape_yara_string(record.email),
        "rdn_serial": escape_yara_string(record.rdn_serial_number),
    }

    return template.render(**context)


def generate_rule_filename(record: CertificateRecord, index: int = 0) -> str:
    """Generate filename for a YARA rule.

    Args:
        record: Certificate record.
        index: Index for unique naming.

    Returns:
        Filename for the rule (without directory path).
    """
    malware_safe = sanitize_name(record.malware_name, "Unknown_Malware", index)
    issuer_safe = sanitize_name(record.cert_issuer_short, "Unknown_Issuer", index)
    serial_safe = sanitize_name(record.cert_serial, "Unknown_Serial", index)

    return f"rule_MAL_Compromised_Cert_{malware_safe}_{issuer_safe}_{serial_safe}.yara"


def generate_rule_name(record: CertificateRecord, index: int = 0) -> str:
    """Generate the YARA rule name.

    Args:
        record: Certificate record.
        index: Index for unique naming.

    Returns:
        YARA rule name.
    """
    malware_safe = sanitize_name(record.malware_name, "Unknown_Malware", index)
    issuer_safe = sanitize_name(record.cert_issuer_short, "Unknown_Issuer", index)
    serial_safe = sanitize_name(record.cert_serial, "Unknown_Serial", index)

    return f"MAL_Compromised_Cert_{malware_safe}_{issuer_safe}_{serial_safe}"


def generate_single_rule(
    record: CertificateRecord,
    output_dir: Path | None = None,
    index: int = 0,
    templates_dir: Path | None = None,
) -> GenerationResult:
    """Generate a single YARA rule file.

    Args:
        record: Certificate record to generate rule for.
        output_dir: Directory to save the rule file.
        index: Index for unique naming.
        templates_dir: Directory containing templates.

    Returns:
        GenerationResult with details of the generation.
    """
    if output_dir is None:
        output_dir = DEFAULT_INDIVIDUAL_DIR

    output_dir.mkdir(parents=True, exist_ok=True)

    filename = generate_rule_filename(record, index)
    rule_path = output_dir / filename
    rule_name = generate_rule_name(record, index)

    try:
        content = generate_rule_content(record, index, templates_dir)
        rule_path.write_text(content, encoding="utf-8")

        logger.debug(f"Generated rule: {rule_path}")

        return GenerationResult(
            rule_path=rule_path,
            rule_name=rule_name,
            certificate_serial=record.cert_serial,
            success=True,
        )
    except Exception as e:
        logger.error(f"Failed to generate rule for {record.cert_serial}: {e}")
        return GenerationResult(
            rule_path=rule_path,
            rule_name=rule_name,
            certificate_serial=record.cert_serial,
            success=False,
            error_message=str(e),
        )


def generate_all_rules(
    records: list[CertificateRecord],
    output_dir: Path | None = None,
    templates_dir: Path | None = None,
) -> list[GenerationResult]:
    """Generate YARA rules for all certificate records.

    Args:
        records: List of certificate records.
        output_dir: Directory to save rule files.
        templates_dir: Directory containing templates.

    Returns:
        List of GenerationResult objects.
    """
    if output_dir is None:
        output_dir = DEFAULT_INDIVIDUAL_DIR

    output_dir.mkdir(parents=True, exist_ok=True)

    results = []
    for index, record in enumerate(records):
        result = generate_single_rule(record, output_dir, index, templates_dir)
        results.append(result)

    success_count = sum(1 for r in results if r.success)
    logger.info(f"Generated {success_count}/{len(results)} YARA rules in {output_dir}")

    return results


def combine_rules(
    input_dir: Path | None = None,
    output_dir: Path | None = None,
    output_filename: str | None = None,
) -> Path:
    """Combine all individual YARA rules into a single file.

    Args:
        input_dir: Directory containing individual rule files.
        output_dir: Directory to save combined file.
        output_filename: Name for the combined file.

    Returns:
        Path to the combined file.
    """
    if input_dir is None:
        input_dir = DEFAULT_INDIVIDUAL_DIR
    if output_dir is None:
        output_dir = DEFAULT_COMBINED_DIR
    if output_filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_filename = f"MAL_Compromised_Cert_{timestamp}.yara"

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / output_filename

    # Collect all rule files
    rule_files = sorted(input_dir.glob("*.yara"))

    if not rule_files:
        logger.warning(f"No YARA rule files found in {input_dir}")
        output_path.write_text('import "pe"\n\n// No rules found\n')
        return output_path

    # Start with single global import
    combined_content = ['import "pe"']

    for rule_file in rule_files:
        # Skip combined files if they somehow ended up in individual dir
        if rule_file.name.startswith("MAL_Compromised_Cert_2"):
            continue

        content = rule_file.read_text(encoding="utf-8")
        # Remove individual import statements
        content = content.replace('import "pe"', "").strip()
        if content:
            combined_content.append(content)

    combined_path = output_path
    combined_path.write_text("\n\n".join(combined_content), encoding="utf-8")

    logger.info(f"Combined {len(rule_files)} rules into {combined_path}")
    return combined_path


def create_zip_archive(
    input_dir: Path | None = None,
    output_dir: Path | None = None,
    output_filename: str = "cert_graveyard_yara_rules.zip",
) -> Path:
    """Create a ZIP archive of all individual YARA rules.

    Args:
        input_dir: Directory containing rule files.
        output_dir: Directory to save the ZIP file.
        output_filename: Name for the ZIP file.

    Returns:
        Path to the created ZIP file.
    """
    if input_dir is None:
        input_dir = DEFAULT_INDIVIDUAL_DIR
    if output_dir is None:
        output_dir = DEFAULT_RULES_DIR

    output_dir.mkdir(parents=True, exist_ok=True)
    zip_path = output_dir / output_filename

    rule_files = list(input_dir.glob("*.yara"))

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for rule_file in rule_files:
            zf.write(rule_file, rule_file.name)

    logger.info(f"Created ZIP archive with {len(rule_files)} rules: {zip_path}")
    return zip_path
