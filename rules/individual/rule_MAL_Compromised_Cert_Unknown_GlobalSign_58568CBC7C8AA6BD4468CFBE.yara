import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_58568CBC7C8AA6BD4468CFBE {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-14"
      version             = "1.0"

      hash                = "95e8f3ce726128b1af15fab165243447cdc0007e8048965151c0769826d47eae"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Nanjing Bangqiao Network Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "58:56:8c:bc:7c:8a:a6:bd:44:68:cf:be"
      cert_thumbprint     = "09CDEE1442AA31F470ED10E76CC0BD138B6D944F"
      cert_valid_from     = "2025-05-14"
      cert_valid_to       = "2026-05-15"

      country             = "CN"
      state               = "Jiangsu"
      locality            = "Nanjing"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "58:56:8c:bc:7c:8a:a6:bd:44:68:cf:be"
      )
}
