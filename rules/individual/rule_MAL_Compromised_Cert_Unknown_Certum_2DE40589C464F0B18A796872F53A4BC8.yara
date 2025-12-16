import "pe"

rule MAL_Compromised_Cert_Unknown_Certum_2DE40589C464F0B18A796872F53A4BC8 {
   meta:
      description         = "Detects Unknown with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-28"
      version             = "1.0"

      hash                = "dcb76c24685fd31d5ac64851fe8e3b41a4462d882eda656fbc7faac89a763f8f"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "厦门市奥裕晖奥物联网科技研究院有限公司"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "2d:e4:05:89:c4:64:f0:b1:8a:79:68:72:f5:3a:4b:c8"
      cert_thumbprint     = "FCDA0A5AD430E00D1AAB802F3634693092D71B95"
      cert_valid_from     = "2025-11-28"
      cert_valid_to       = "2026-11-28"

      country             = "CN"
      state               = "福建省"
      locality            = "厦门市"
      email               = "???"
      rdn_serial_number   = "91350206MAEAJ7AQ0G"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "2d:e4:05:89:c4:64:f0:b1:8a:79:68:72:f5:3a:4b:c8"
      )
}
