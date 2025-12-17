import "pe"

rule MAL_Compromised_Cert_RustyStealer_Certum_1616F14FBA9C87AB97AD25861EE7A9DC {
   meta:
      description         = "Detects RustyStealer with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-27"
      version             = "1.0"

      hash                = "0b44a1854f9dc2eab5625dffc1ceb17b1e89773c9ee04802a2f40dfd834dec2c"
      malware             = "RustyStealer"
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
