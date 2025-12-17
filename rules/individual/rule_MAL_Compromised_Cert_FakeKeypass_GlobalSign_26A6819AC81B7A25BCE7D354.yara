import "pe"

rule MAL_Compromised_Cert_FakeKeypass_GlobalSign_26A6819AC81B7A25BCE7D354 {
   meta:
      description         = "Detects FakeKeypass with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-02-22"
      version             = "1.0"

      hash                = "128a68a714f2f6002f5e8e8cfe0bbae10cd2ffe63d30c8acc00255b9659ce121"
      malware             = "FakeKeypass"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "MekoGuard Bytemin Information Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "26:a6:81:9a:c8:1b:7a:25:bc:e7:d3:54"
      cert_thumbprint     = "A53E2045C456BC5879E1159245884740FF0BE11D"
      cert_valid_from     = "2024-02-22"
      cert_valid_to       = "2025-02-06"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Foshan"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "26:a6:81:9a:c8:1b:7a:25:bc:e7:d3:54"
      )
}
