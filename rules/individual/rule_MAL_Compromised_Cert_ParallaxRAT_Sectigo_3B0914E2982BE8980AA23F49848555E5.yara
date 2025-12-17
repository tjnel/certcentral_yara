import "pe"

rule MAL_Compromised_Cert_ParallaxRAT_Sectigo_3B0914E2982BE8980AA23F49848555E5 {
   meta:
      description         = "Detects ParallaxRAT with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-01-26"
      version             = "1.0"

      hash                = "c4ca06766b0b2f5a7aeb24aa39d3b3695bcbe94b96a506dd9950e795064d875c"
      malware             = "ParallaxRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "Office Rat s.r.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "3b:09:14:e2:98:2b:e8:98:0a:a2:3f:49:84:85:55:e5"
      cert_thumbprint     = "32640A143458C8543EEC7E2438D0518EAE8A8AB9"
      cert_valid_from     = "2022-01-26"
      cert_valid_to       = "2023-01-26"

      country             = "CZ"
      state               = "Plzeňský kraj"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "3b:09:14:e2:98:2b:e8:98:0a:a2:3f:49:84:85:55:e5"
      )
}
