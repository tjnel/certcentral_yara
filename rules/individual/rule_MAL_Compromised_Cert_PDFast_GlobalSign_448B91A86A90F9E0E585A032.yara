import "pe"

rule MAL_Compromised_Cert_PDFast_GlobalSign_448B91A86A90F9E0E585A032 {
   meta:
      description         = "Detects PDFast with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-04-25"
      version             = "1.0"

      hash                = "2ef67a07ced37631e6984f98a8ee249164a25da79358e0a0461ab50ac0b02f8f"
      malware             = "PDFast"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "HOTEL FATAZ (PRIVATE) LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "44:8b:91:a8:6a:90:f9:e0:e5:85:a0:32"
      cert_thumbprint     = "68BFBA3FC7ABD9D8727DBA1DB15F161E69FB09CE"
      cert_valid_from     = "2024-04-25"
      cert_valid_to       = "2025-04-26"

      country             = "PK"
      state               = "Sindh"
      locality            = "Hyderabad"
      email               = "reema77ik@gmail.com"
      rdn_serial_number   = "0004890"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "44:8b:91:a8:6a:90:f9:e0:e5:85:a0:32"
      )
}
