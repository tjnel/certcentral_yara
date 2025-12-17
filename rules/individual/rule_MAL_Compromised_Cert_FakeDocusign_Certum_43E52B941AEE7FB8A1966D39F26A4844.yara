import "pe"

rule MAL_Compromised_Cert_FakeDocusign_Certum_43E52B941AEE7FB8A1966D39F26A4844 {
   meta:
      description         = "Detects FakeDocusign with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-31"
      version             = "1.0"

      hash                = "f788cb3d8e4196bb14c0519514e4bcf8a6a7a927a9bde076fb37f7791f81c786"
      malware             = "FakeDocusign"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Taiyuan Jiankang Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "43:e5:2b:94:1a:ee:7f:b8:a1:96:6d:39:f2:6a:48:44"
      cert_thumbprint     = "2BD0C974AAD9F5151E31C715381592769D608C7B"
      cert_valid_from     = "2025-07-31"
      cert_valid_to       = "2026-07-31"

      country             = "CN"
      state               = "山西省"
      locality            = "太原市"
      email               = "???"
      rdn_serial_number   = "91140106MA0M4WL26F"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "43:e5:2b:94:1a:ee:7f:b8:a1:96:6d:39:f2:6a:48:44"
      )
}
