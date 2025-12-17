import "pe"

rule MAL_Compromised_Cert_ParallaxRAT_Sectigo_74FC9257BC86F8C618501695AD4B1606 {
   meta:
      description         = "Detects ParallaxRAT with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-09-28"
      version             = "1.0"

      hash                = "58a6a07940b4e3f69415097f67f8062938290677d0c9632f29a8facddd2de46f"
      malware             = "ParallaxRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "169Teaco Limited"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "74:fc:92:57:bc:86:f8:c6:18:50:16:95:ad:4b:16:06"
      cert_thumbprint     = "C6F9CAD38279E78EF4D0624221D40D6ACDE14966"
      cert_valid_from     = "2021-09-28"
      cert_valid_to       = "2022-09-28"

      country             = "CA"
      state               = "Ontario"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "74:fc:92:57:bc:86:f8:c6:18:50:16:95:ad:4b:16:06"
      )
}
