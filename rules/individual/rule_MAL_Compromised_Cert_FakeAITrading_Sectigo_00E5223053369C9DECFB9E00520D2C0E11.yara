import "pe"

rule MAL_Compromised_Cert_FakeAITrading_Sectigo_00E5223053369C9DECFB9E00520D2C0E11 {
   meta:
      description         = "Detects FakeAITrading with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-12"
      version             = "1.0"

      hash                = "9bced85d047b39994ad10094d74b18322f0fd51517e3ca2d6c2a069fe46ab149"
      malware             = "FakeAITrading"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Taiyuan Leweiqu E-commerce Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:e5:22:30:53:36:9c:9d:ec:fb:9e:00:52:0d:2c:0e:11"
      cert_thumbprint     = "4A9BD948924E7E67AF8A268CFAA3CA36CDECD675"
      cert_valid_from     = "2025-06-12"
      cert_valid_to       = "2026-06-12"

      country             = "CN"
      state               = "Shanxi Sheng"
      locality            = ""
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:e5:22:30:53:36:9c:9d:ec:fb:9e:00:52:0d:2c:0e:11"
      )
}
