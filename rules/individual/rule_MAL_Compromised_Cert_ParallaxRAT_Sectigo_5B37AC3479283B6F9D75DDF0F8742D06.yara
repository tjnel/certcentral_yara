import "pe"

rule MAL_Compromised_Cert_ParallaxRAT_Sectigo_5B37AC3479283B6F9D75DDF0F8742D06 {
   meta:
      description         = "Detects ParallaxRAT with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-04-30"
      version             = "1.0"

      hash                = "a7fab8c1fc7ffc5002452f5a783f7a43b263ad302fab8d9fdd412610122f77ce"
      malware             = "ParallaxRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "ART BOOK PHOTO s.r.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "5b:37:ac:34:79:28:3b:6f:9d:75:dd:f0:f8:74:2d:06"
      cert_thumbprint     = "48F745BDA9A47F48D798E4F71B81B9560EBAC141"
      cert_valid_from     = "2021-04-30"
      cert_valid_to       = "2022-04-30"

      country             = "CZ"
      state               = "???"
      locality            = "Javorník"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "5b:37:ac:34:79:28:3b:6f:9d:75:dd:f0:f8:74:2d:06"
      )
}
