import "pe"

rule MAL_Compromised_Cert_ParallaxRAT_Sectigo_77550ED697992B397E3F1AD8E2A662D1 {
   meta:
      description         = "Detects ParallaxRAT with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-03-22"
      version             = "1.0"

      hash                = "517af63bf54611b1ae3707b905aa9263c3e139dc576acc53ee1cf34e75c3ac7a"
      malware             = "ParallaxRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "GRASS RAIN, s.r.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "77:55:0e:d6:97:99:2b:39:7e:3f:1a:d8:e2:a6:62:d1"
      cert_thumbprint     = "525426938BB20CB83887BCB852CF5BC9B0D4B10E"
      cert_valid_from     = "2022-03-22"
      cert_valid_to       = "2023-03-22"

      country             = "SK"
      state               = "Trnavský kraj"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "77:55:0e:d6:97:99:2b:39:7e:3f:1a:d8:e2:a6:62:d1"
      )
}
