import "pe"

rule MAL_Compromised_Cert_Unknown_Certum_06EFE8AF86B12D497A3610D222EA59C0 {
   meta:
      description         = "Detects Unknown with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-07"
      version             = "1.0"

      hash                = "3a4fcfc2d47067d7acf25e2a0808d9282a4c574a530b7154aba38ea8dd981789"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Open Source Developer, Zixu Wang"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "06:ef:e8:af:86:b1:2d:49:7a:36:10:d2:22:ea:59:c0"
      cert_thumbprint     = "5EE1BFB8ABE1D5656EF57138715F08379E5C0948"
      cert_valid_from     = "2025-03-07"
      cert_valid_to       = "2026-03-07"

      country             = "CN"
      state               = "Anhui"
      locality            = "Hefei"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "06:ef:e8:af:86:b1:2d:49:7a:36:10:d2:22:ea:59:c0"
      )
}
