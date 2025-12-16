import "pe"

rule MAL_Compromised_Cert_FakeKeePass_Sectigo_00E1D5029BF74F42040BB14B402FC3B9D0 {
   meta:
      description         = "Detects FakeKeePass with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-20"
      version             = "1.0"

      hash                = "f56f014405aeda11b474c9c9628dcce6633df33f8ca493b6caae9e072860e308"
      malware             = "FakeKeePass"
      malware_type        = "Unknown"
      malware_notes       = "https://app.any.run/tasks/d6916baa-68ac-4eaf-b098-43fb0cafcf43"

      signer              = "Jinan Lu'an Information Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:e1:d5:02:9b:f7:4f:42:04:0b:b1:4b:40:2f:c3:b9:d0"
      cert_thumbprint     = "8B12A0E1D6E2A0CBBFCDD5EC073E3217684105A7"
      cert_valid_from     = "2025-10-20"
      cert_valid_to       = "2026-10-20"

      country             = "CN"
      state               = "Shandong Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91370100MA94FUXT8E"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:e1:d5:02:9b:f7:4f:42:04:0b:b1:4b:40:2f:c3:b9:d0"
      )
}
