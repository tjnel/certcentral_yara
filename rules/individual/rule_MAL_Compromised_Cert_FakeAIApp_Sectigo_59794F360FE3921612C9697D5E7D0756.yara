import "pe"

rule MAL_Compromised_Cert_FakeAIApp_Sectigo_59794F360FE3921612C9697D5E7D0756 {
   meta:
      description         = "Detects FakeAIApp with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-08"
      version             = "1.0"

      hash                = "574f83a420f60ba9b94e03c8f1c1c3afb2de975ef181d02dcc68d3ed41a49133"
      malware             = "FakeAIApp"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Hefei Qiangwei Network Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "59:79:4f:36:0f:e3:92:16:12:c9:69:7d:5e:7d:07:56"
      cert_thumbprint     = "17BEFB4F12AB4138D2D7970FDC4110A047ABF701"
      cert_valid_from     = "2025-08-08"
      cert_valid_to       = "2026-08-08"

      country             = "CN"
      state               = "Anhui Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "59:79:4f:36:0f:e3:92:16:12:c9:69:7d:5e:7d:07:56"
      )
}
