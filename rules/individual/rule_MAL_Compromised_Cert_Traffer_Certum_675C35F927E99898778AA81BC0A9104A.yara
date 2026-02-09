import "pe"

rule MAL_Compromised_Cert_Traffer_Certum_675C35F927E99898778AA81BC0A9104A {
   meta:
      description         = "Detects Traffer with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-06"
      version             = "1.0"

      hash                = "71105ac7ede3c17828968a11af58ddfcebc3b2f0134765b67ca831c53a82f01a"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = "Fake Kakao Talk meeting installer targeting crypto users worldwide"

      signer              = "Heze Qinfei Network Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "67:5c:35:f9:27:e9:98:98:77:8a:a8:1b:c0:a9:10:4a"
      cert_thumbprint     = "CD0F47F474DC853B12468853453DC44BA0D00360"
      cert_valid_from     = "2025-12-06"
      cert_valid_to       = "2026-12-06"

      country             = "CN"
      state               = "Shandong"
      locality            = "Heze"
      email               = "???"
      rdn_serial_number   = "91371702MAC81U8R5M"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "67:5c:35:f9:27:e9:98:98:77:8a:a8:1b:c0:a9:10:4a"
      )
}
