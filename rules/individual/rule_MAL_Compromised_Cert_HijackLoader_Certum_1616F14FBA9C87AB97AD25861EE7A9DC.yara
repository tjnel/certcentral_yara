import "pe"

rule MAL_Compromised_Cert_HijackLoader_Certum_1616F14FBA9C87AB97AD25861EE7A9DC {
   meta:
      description         = "Detects HijackLoader with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-27"
      version             = "1.0"

      hash                = "c20e98a4190f9063f9181d8d9fc01bb89e4e56cb888d4d8883c593586ff52a09"
      malware             = "HijackLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Hangzhou Rongyi Network Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "16:16:f1:4f:ba:9c:87:ab:97:ad:25:86:1e:e7:a9:dc"
      cert_thumbprint     = "DCC865C6DD9EA2318439F207ACBC2AC0797FB51B"
      cert_valid_from     = "2024-09-27"
      cert_valid_to       = "2025-09-27"

      country             = "CN"
      state               = "Zhejiang"
      locality            = "Hangzhou"
      email               = "???"
      rdn_serial_number   = "91330185MA280YDY16"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "16:16:f1:4f:ba:9c:87:ab:97:ad:25:86:1e:e7:a9:dc"
      )
}
