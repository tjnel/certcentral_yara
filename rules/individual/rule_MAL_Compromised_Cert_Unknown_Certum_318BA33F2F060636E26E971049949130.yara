import "pe"

rule MAL_Compromised_Cert_Unknown_Certum_318BA33F2F060636E26E971049949130 {
   meta:
      description         = "Detects Unknown with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-04"
      version             = "1.0"

      hash                = "18844d402ccdfcc6a1e7f5104ace53b62c517ac2f904dd75393fc1db0dc5af6a"
      malware             = "Unknown"
      malware_type        = "Infostealer"
      malware_notes       = "This malware contains a signed copy of Virtual Here which allows remote usage of USB devices. It was reportedly dropped from the IP 178.16.55.189 by Amadey malware."

      signer              = "Taiyuan Banmin Trading Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "31:8b:a3:3f:2f:06:06:36:e2:6e:97:10:49:94:91:30"
      cert_thumbprint     = "2E0725E64DFBB5AE4EFE9233DEEF033CCAE8F376"
      cert_valid_from     = "2025-12-04"
      cert_valid_to       = "2026-12-04"

      country             = "CN"
      state               = "Shanxi"
      locality            = "Taiyuan"
      email               = "???"
      rdn_serial_number   = "91140105MADDDUAN7A"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "31:8b:a3:3f:2f:06:06:36:e2:6e:97:10:49:94:91:30"
      )
}
