import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_5867CAD98B5C8552F60A7BD8 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-03-30"
      version             = "1.0"

      hash                = "a82da08a181eafbcc779f5af962eebe04e3b973c40f90a37f42ea8d3de7fc70f"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xuaony Plantain E-Commerce Trading Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "58:67:ca:d9:8b:5c:85:52:f6:0a:7b:d8"
      cert_thumbprint     = "C23686C7F96871D88754C70138702D5DCC35AC6D"
      cert_valid_from     = "2024-03-30"
      cert_valid_to       = "2025-03-30"

      country             = "CN"
      state               = "Hubei"
      locality            = "Xiangyang"
      email               = "???"
      rdn_serial_number   = "91420600MACLU7R889"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "58:67:ca:d9:8b:5c:85:52:f6:0a:7b:d8"
      )
}
