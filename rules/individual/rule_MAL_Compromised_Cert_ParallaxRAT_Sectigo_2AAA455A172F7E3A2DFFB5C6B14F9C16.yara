import "pe"

rule MAL_Compromised_Cert_ParallaxRAT_Sectigo_2AAA455A172F7E3A2DFFB5C6B14F9C16 {
   meta:
      description         = "Detects ParallaxRAT with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-12-14"
      version             = "1.0"

      hash                = "7852cf2dfe60b60194dae9b037298ed0a9c84fa1d850f3898751575f4377215f"
      malware             = "ParallaxRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "DREAM VILLAGE s.r.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "2a:aa:45:5a:17:2f:7e:3a:2d:ff:b5:c6:b1:4f:9c:16"
      cert_thumbprint     = "23C91B66BD07E56E60724B0064D4FEDBDB1C8913"
      cert_valid_from     = "2021-12-14"
      cert_valid_to       = "2022-12-14"

      country             = "CZ"
      state               = "Praha, Hlavní město"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "2a:aa:45:5a:17:2f:7e:3a:2d:ff:b5:c6:b1:4f:9c:16"
      )
}
