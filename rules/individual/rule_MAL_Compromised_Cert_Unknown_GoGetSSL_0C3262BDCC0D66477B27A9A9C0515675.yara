import "pe"

rule MAL_Compromised_Cert_Unknown_GoGetSSL_0C3262BDCC0D66477B27A9A9C0515675 {
   meta:
      description         = "Detects Unknown with compromised cert (GoGetSSL)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-14"
      version             = "1.0"

      hash                = "427f5549a9f028096ac3f6b4a5fd2332d3b3037195775c27b3515ad2479b3cb9"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Hoen Industries LLC"
      cert_issuer_short   = "GoGetSSL"
      cert_issuer         = "GoGetSSL G4 CS RSA4096 SHA256 2022 CA-1"
      cert_serial         = "0c:32:62:bd:cc:0d:66:47:7b:27:a9:a9:c0:51:56:75"
      cert_thumbprint     = "513407319B0B36AD6CA7F65631BF9FB71798FB36"
      cert_valid_from     = "2025-03-14"
      cert_valid_to       = "2026-03-05"

      country             = "US"
      state               = "Florida"
      locality            = "Palm Bay"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GoGetSSL G4 CS RSA4096 SHA256 2022 CA-1" and
         sig.serial == "0c:32:62:bd:cc:0d:66:47:7b:27:a9:a9:c0:51:56:75"
      )
}
