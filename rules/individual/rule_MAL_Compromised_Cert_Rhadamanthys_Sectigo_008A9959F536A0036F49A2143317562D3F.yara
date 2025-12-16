import "pe"

rule MAL_Compromised_Cert_Rhadamanthys_Sectigo_008A9959F536A0036F49A2143317562D3F {
   meta:
      description         = "Detects Rhadamanthys with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-24"
      version             = "1.0"

      hash                = "5ffb8425cda8783801a4898b6d6db1f8398962af554b1371021d372e2358039b"
      malware             = "Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "Redstrikevn Company Limited"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV E36"
      cert_serial         = "00:8a:99:59:f5:36:a0:03:6f:49:a2:14:33:17:56:2d:3f"
      cert_thumbprint     = "4D36C5325245186319D22BB933EE4C9289FAC559"
      cert_valid_from     = "2025-01-24"
      cert_valid_to       = "2026-01-16"

      country             = "VN"
      state               = "Ho Chi Minh"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "0318798119"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV E36" and
         sig.serial == "00:8a:99:59:f5:36:a0:03:6f:49:a2:14:33:17:56:2d:3f"
      )
}
