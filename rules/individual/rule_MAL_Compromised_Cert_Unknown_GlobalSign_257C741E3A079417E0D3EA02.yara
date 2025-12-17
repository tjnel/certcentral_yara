import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_257C741E3A079417E0D3EA02 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-27"
      version             = "1.0"

      hash                = "ac14ed8e38f5b78ff5047d8af38b3e174ac87da526a7690fb924c7a056632600"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "UCon Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "25:7c:74:1e:3a:07:94:17:e0:d3:ea:02"
      cert_thumbprint     = "8E11CC942E392D582E337382B2618F1E64349649"
      cert_valid_from     = "2025-05-27"
      cert_valid_to       = "2026-04-25"

      country             = "CN"
      state               = "GUANGDONG"
      locality            = "SHENZHEN"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "25:7c:74:1e:3a:07:94:17:e0:d3:ea:02"
      )
}
