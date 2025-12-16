import "pe"

rule MAL_Compromised_Cert_OneStart_DigiCert_09561E1A16C2BE16570AC674712B56F1 {
   meta:
      description         = "Detects OneStart with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-16"
      version             = "1.0"

      hash                = "5e1689ca04778ff0c5764abc50b023bd71b9ab7841a40f425c5fee4b798f8e11"
      malware             = "OneStart"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "OneStart Technologies LLC"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "09:56:1e:1a:16:c2:be:16:57:0a:c6:74:71:2b:56:f1"
      cert_thumbprint     = "612DE79A0369AFF3507DEF7A39DF2F4F7A82E51D"
      cert_valid_from     = "2025-05-16"
      cert_valid_to       = "2026-03-18"

      country             = "US"
      state               = "Delaware"
      locality            = "Dover"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "09:56:1e:1a:16:c2:be:16:57:0a:c6:74:71:2b:56:f1"
      )
}
