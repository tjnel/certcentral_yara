import "pe"

rule MAL_Compromised_Cert_RomCom_DigiCert_071D4C6EB644BCF348FA54890038C4F2 {
   meta:
      description         = "Detects RomCom with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-07"
      version             = "1.0"

      hash                = "0cae3b04919050963b4413a43d10fcd7ea4b3f332234ee6c65dcceee7a0833e5"
      malware             = "RomCom"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "XRYUS TECHNOLOGIES CORPORATION"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "07:1d:4c:6e:b6:44:bc:f3:48:fa:54:89:00:38:c4:f2"
      cert_thumbprint     = "53F8A124BFCF5A42924272F25854D26E82D21C37"
      cert_valid_from     = "2025-04-07"
      cert_valid_to       = "2027-04-07"

      country             = "JP"
      state               = "Tokyo"
      locality            = "Minato-ku"
      email               = "???"
      rdn_serial_number   = "2900-01-095356"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "07:1d:4c:6e:b6:44:bc:f3:48:fa:54:89:00:38:c4:f2"
      )
}
