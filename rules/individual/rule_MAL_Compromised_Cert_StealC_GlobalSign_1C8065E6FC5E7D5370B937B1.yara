import "pe"

rule MAL_Compromised_Cert_StealC_GlobalSign_1C8065E6FC5E7D5370B937B1 {
   meta:
      description         = "Detects StealC with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-29"
      version             = "1.0"

      hash                = "19588db4bc98090955e95c3bef81c946fa593c7e3d2aa3dfbf57b213b7e16360"
      malware             = "StealC"
      malware_type        = "Infostealer"
      malware_notes       = "A popular and customizable infostealler that can also function as a loader: https://blog.sekoia.io/stealc-a-copycat-of-vidar-and-raccoon-infostealers-gaining-in-popularity-part-1/"

      signer              = "TECH SOLUTIONS BHAM INC."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "1c:80:65:e6:fc:5e:7d:53:70:b9:37:b1"
      cert_thumbprint     = "392CA9AE72072971CC24384B4E009C40F657862F"
      cert_valid_from     = "2024-10-29"
      cert_valid_to       = "2025-10-30"

      country             = "US"
      state               = "Alabama"
      locality            = "Birmingham"
      email               = "???"
      rdn_serial_number   = "000-826-105"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "1c:80:65:e6:fc:5e:7d:53:70:b9:37:b1"
      )
}
