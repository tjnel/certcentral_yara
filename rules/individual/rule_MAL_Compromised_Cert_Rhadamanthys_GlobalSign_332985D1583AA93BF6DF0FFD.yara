import "pe"

rule MAL_Compromised_Cert_Rhadamanthys_GlobalSign_332985D1583AA93BF6DF0FFD {
   meta:
      description         = "Detects Rhadamanthys with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-07"
      version             = "1.0"

      hash                = "42735792cc7e76b7439751d4aa673d5bd61d100f8d4de42c9084db46e2a1dbf1"
      malware             = "Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "THINH HA TRADE & TRANSPORT COMPANY LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 CodeSigning CA 2020"
      cert_serial         = "33:29:85:d1:58:3a:a9:3b:f6:df:0f:fd"
      cert_thumbprint     = "35EABD502F8EDD37DD62B3C598167BF60E0226D5"
      cert_valid_from     = "2025-03-07"
      cert_valid_to       = "2026-03-08"

      country             = "VN"
      state               = "Ha Nam"
      locality            = "Ha Nam"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 CodeSigning CA 2020" and
         sig.serial == "33:29:85:d1:58:3a:a9:3b:f6:df:0f:fd"
      )
}
