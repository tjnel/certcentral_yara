import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_14B8959733633025188B7DC5 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-13"
      version             = "1.0"

      hash                = "030a8c9e64d92039e9b2b9a04337d303374964f52322a652ccda2b7080e796e6"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Zhiya Yunke (Chengdu) Finance and Tax Service Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "14:b8:95:97:33:63:30:25:18:8b:7d:c5"
      cert_thumbprint     = "CDE26E0B01C7129ADE41702BD42204F18781109F"
      cert_valid_from     = "2025-06-13"
      cert_valid_to       = "2026-06-14"

      country             = "CN"
      state               = "Sichuan"
      locality            = "Chengdu"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "14:b8:95:97:33:63:30:25:18:8b:7d:c5"
      )
}
