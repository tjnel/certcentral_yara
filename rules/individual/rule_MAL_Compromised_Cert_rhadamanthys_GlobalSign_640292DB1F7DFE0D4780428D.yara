import "pe"

rule MAL_Compromised_Cert_rhadamanthys_GlobalSign_640292DB1F7DFE0D4780428D {
   meta:
      description         = "Detects rhadamanthys with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-19"
      version             = "1.0"

      hash                = "434548803c79dbf1d6627e039b99c5e9481f3413eaae4e27b8a2e2e0bd41519a"
      malware             = "rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "OOO Pandora"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "64:02:92:db:1f:7d:fe:0d:47:80:42:8d"
      cert_thumbprint     = "9E15BD691057FC9ECEC0DA7A3389D47A0B0F1A20"
      cert_valid_from     = "2025-02-19"
      cert_valid_to       = "2026-02-20"

      country             = "RU"
      state               = "Saint Petersburg"
      locality            = "Saint Petersburg"
      email               = "pandoracomp@mail.ru"
      rdn_serial_number   = "1187847297318"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "64:02:92:db:1f:7d:fe:0d:47:80:42:8d"
      )
}
