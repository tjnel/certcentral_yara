import "pe"

rule MAL_Compromised_Cert_ParallaxRAT_Sectigo_292EB1133507F42E6F36C5549C189D5E {
   meta:
      description         = "Detects ParallaxRAT with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-12-06"
      version             = "1.0"

      hash                = "f0b3b36086e58964bf4b9d655568ab5c7f798bd89e7a8581069e65f8189c0b79"
      malware             = "ParallaxRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "Affairs-case s.r.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "29:2e:b1:13:35:07:f4:2e:6f:36:c5:54:9c:18:9d:5e"
      cert_thumbprint     = "48C32548FF651E2AAC12716EFB448F5583577E35"
      cert_valid_from     = "2021-12-06"
      cert_valid_to       = "2022-12-06"

      country             = "CZ"
      state               = "Praha, Hlavní město"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "29:2e:b1:13:35:07:f4:2e:6f:36:c5:54:9c:18:9d:5e"
      )
}
