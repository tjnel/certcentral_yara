import "pe"

rule MAL_Compromised_Cert_Gh0stRAT_Certum_5F737E82330734C32297EF89B72FB607 {
   meta:
      description         = "Detects Gh0stRAT with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-22"
      version             = "1.0"

      hash                = "349b54f136e63904ed5a1b3921d8744d3815592690f9167aedd3ead075ced9a4"
      malware             = "Gh0stRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Keroro Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "5f:73:7e:82:33:07:34:c3:22:97:ef:89:b7:2f:b6:07"
      cert_thumbprint     = "4CE7B99C56D5EFE4FCE93D71010D53941C3A635A"
      cert_valid_from     = "2025-02-22"
      cert_valid_to       = "2026-02-22"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Shenzhen"
      email               = "???"
      rdn_serial_number   = "91440300MA5FAR1W6E"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "5f:73:7e:82:33:07:34:c3:22:97:ef:89:b7:2f:b6:07"
      )
}
