import "pe"

rule MAL_Compromised_Cert_Unknown_Certum_4B4E50838A7D85CA0C5EA67AE3FAAD05 {
   meta:
      description         = "Detects Unknown with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-25"
      version             = "1.0"

      hash                = "17b90db39a741357e017bdc387ad781a32dcc99d34b7f56d52ad82998634d098"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Liv Software Ltd"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "4b:4e:50:83:8a:7d:85:ca:0c:5e:a6:7a:e3:fa:ad:05"
      cert_thumbprint     = "DCEC436283F37C9A7BEE8D4E5D4374474086E4CD"
      cert_valid_from     = "2024-06-25"
      cert_valid_to       = "2025-06-25"

      country             = "GB"
      state               = "???"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "13045338"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "4b:4e:50:83:8a:7d:85:ca:0c:5e:a6:7a:e3:fa:ad:05"
      )
}
