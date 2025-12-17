import "pe"

rule MAL_Compromised_Cert_StealC_GlobalSign_64D320BA7835B7EABB35090B {
   meta:
      description         = "Detects StealC with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-23"
      version             = "1.0"

      hash                = "bc2bc7928859d26e604daed7b33666700b36b34e04987c172f5bca7e62deb97b"
      malware             = "StealC"
      malware_type        = "Infostealer"
      malware_notes       = "A popular and customizable infostealler that can also function as a loader: https://blog.sekoia.io/stealc-a-copycat-of-vidar-and-raccoon-infostealers-gaining-in-popularity-part-1/"

      signer              = "LLC Private security company SHCHIT-A"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "64:d3:20:ba:78:35:b7:ea:bb:35:09:0b"
      cert_thumbprint     = "095432D2CB45882288E1E7B4832E5AA572A39408"
      cert_valid_from     = "2025-05-23"
      cert_valid_to       = "2026-05-24"

      country             = "RU"
      state               = "Moscow Oblast"
      locality            = "Lytkarino"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "64:d3:20:ba:78:35:b7:ea:bb:35:09:0b"
      )
}
