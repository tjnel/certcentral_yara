import "pe"

rule MAL_Compromised_Cert_FakeAITrading_Sectigo_009E4FD3EDA695BDECB946493D67665410 {
   meta:
      description         = "Detects FakeAITrading with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-08"
      version             = "1.0"

      hash                = "98da8634c17e724d7d457126dce1149c75c27bf08ea1bc7d34b5e77cc9f0205a"
      malware             = "FakeAITrading"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "海口市勤莱佳科技有限公司"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:9e:4f:d3:ed:a6:95:bd:ec:b9:46:49:3d:67:66:54:10"
      cert_thumbprint     = "2C13C76F10DDB1BBAA1DAA6E06EA2A977B924877"
      cert_valid_from     = "2025-04-08"
      cert_valid_to       = "2026-04-08"

      country             = "CN"
      state               = "海南省"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:9e:4f:d3:ed:a6:95:bd:ec:b9:46:49:3d:67:66:54:10"
      )
}
