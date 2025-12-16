import "pe"

rule MAL_Compromised_Cert_Hijackloader_Sectigo_1C994A9835179192411AA84E612605E2 {
   meta:
      description         = "Detects Hijackloader with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-10"
      version             = "1.0"

      hash                = "0ebeaff5e5d71ca949825a421d8a0c4f1459548a17c27ab0698a6393939b4f64"
      malware             = "Hijackloader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Taiyuan Jingqu Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "1c:99:4a:98:35:17:91:92:41:1a:a8:4e:61:26:05:e2"
      cert_thumbprint     = "F0C31342637ABC28D0C4621F6D9C7884B2B10C67"
      cert_valid_from     = "2025-09-10"
      cert_valid_to       = "2026-09-10"

      country             = "CN"
      state               = "Shanxi Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "1c:99:4a:98:35:17:91:92:41:1a:a8:4e:61:26:05:e2"
      )
}
