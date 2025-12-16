import "pe"

rule MAL_Compromised_Cert_ValleyRAT_Certum_5EAC92D72A8D601A4E4833703F78001D {
   meta:
      description         = "Detects ValleyRAT with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-29"
      version             = "1.0"

      hash                = "65537499abd5e2915a79d1df00fcf6adb9d17628f9cb5ae26d8b45303333c523"
      malware             = "ValleyRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "成都航迈源动科技有限公司"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "5e:ac:92:d7:2a:8d:60:1a:4e:48:33:70:3f:78:00:1d"
      cert_thumbprint     = "54871153335B5ED2AC9EA5101327CCFB726E9431"
      cert_valid_from     = "2025-08-29"
      cert_valid_to       = "2026-08-29"

      country             = "CN"
      state               = "四川"
      locality            = "成都"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "5e:ac:92:d7:2a:8d:60:1a:4e:48:33:70:3f:78:00:1d"
      )
}
