import "pe"

rule MAL_Compromised_Cert_Unknown_Certum_3F28800AEF9A143AC2BCAC569D44788F {
   meta:
      description         = "Detects Unknown with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-24"
      version             = "1.0"

      hash                = "9900e3bc74c9dc9886d8e5c4395700d0b1b1533f51ac763fa157a7307c333ab6"
      malware             = "Unknown"
      malware_type        = "Remote access tool"
      malware_notes       = "The malware installs a tool called Remote Manipulator System and creates a Windows Defender exclusion for the whole C drive. https://tria.ge/251208-pxs38sdz4b/behavioral2"

      signer              = "Tianjin Oudi Zhixin Information Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "3f:28:80:0a:ef:9a:14:3a:c2:bc:ac:56:9d:44:78:8f"
      cert_thumbprint     = "2C0F66DC2ECBEFDF0E71D3DC1A1E4476621E990D"
      cert_valid_from     = "2025-11-24"
      cert_valid_to       = "2026-11-24"

      country             = "CN"
      state               = "Tianjin"
      locality            = "Tianjin"
      email               = "???"
      rdn_serial_number   = "91120104MABX7QN37W"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "3f:28:80:0a:ef:9a:14:3a:c2:bc:ac:56:9d:44:78:8f"
      )
}
