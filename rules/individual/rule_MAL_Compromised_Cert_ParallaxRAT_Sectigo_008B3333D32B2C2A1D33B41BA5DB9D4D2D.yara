import "pe"

rule MAL_Compromised_Cert_ParallaxRAT_Sectigo_008B3333D32B2C2A1D33B41BA5DB9D4D2D {
   meta:
      description         = "Detects ParallaxRAT with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-05-03"
      version             = "1.0"

      hash                = "5d5684ccef3ce3b6e92405f73794796e131d3cb1424d757828c3fb62f70f6227"
      malware             = "ParallaxRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "BOOK CAFÉ, s.r.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:8b:33:33:d3:2b:2c:2a:1d:33:b4:1b:a5:db:9d:4d:2d"
      cert_thumbprint     = "7ECAA9A507A6672144A82D453413591067FC1D27"
      cert_valid_from     = "2021-05-03"
      cert_valid_to       = "2022-05-03"

      country             = "CZ"
      state               = "???"
      locality            = "Brno"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:8b:33:33:d3:2b:2c:2a:1d:33:b4:1b:a5:db:9d:4d:2d"
      )
}
