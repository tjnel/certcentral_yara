import "pe"

rule MAL_Compromised_Cert_FakeDocument_Certum_64065DA5F28814E1470536854F7D0162 {
   meta:
      description         = "Detects FakeDocument with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-25"
      version             = "1.0"

      hash                = "d57ad188853f4cee282adcb3672d23906dd42a0e4c3e0cde734c128235644ede"
      malware             = "FakeDocument"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Ionik Software Ltd"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "64:06:5d:a5:f2:88:14:e1:47:05:36:85:4f:7d:01:62"
      cert_thumbprint     = "2127820DAF3405488BA2E6330A918EBAD6DE3720"
      cert_valid_from     = "2024-10-25"
      cert_valid_to       = "2025-10-25"

      country             = "GB"
      state               = "???"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "64:06:5d:a5:f2:88:14:e1:47:05:36:85:4f:7d:01:62"
      )
}
