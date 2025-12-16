import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Sectigo_00D703B2786230CDC702B125CA3C29C593 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-26"
      version             = "1.0"

      hash                = "89ff68d2f4790bc23a3cd8860c9aa5c055ef2d133ae4de62d655ab778774f407"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "PANTALACCI ESSINDI EDANG (ESSINDI MICKAEL)"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:d7:03:b2:78:62:30:cd:c7:02:b1:25:ca:3c:29:c5:93"
      cert_thumbprint     = "87AB152DA67F15F7133B104668A71718C3C84DA1"
      cert_valid_from     = "2025-11-26"
      cert_valid_to       = "2026-11-26"

      country             = "FR"
      state               = "Ile-de-France"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "792 801 896"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:d7:03:b2:78:62:30:cd:c7:02:b1:25:ca:3c:29:c5:93"
      )
}
