import "pe"

rule MAL_Compromised_Cert_ParallaxRAT_Sectigo_59A57E8BA3DCF2B6F59981FDA14B03 {
   meta:
      description         = "Detects ParallaxRAT with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-12-28"
      version             = "1.0"

      hash                = "d9ace2d97010316fdb0f416920232e8d4c59b01614633c4d5def79abb15d0175"
      malware             = "ParallaxRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "Medium LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "59:a5:7e:8b:a3:dc:f2:b6:f5:99:81:fd:a1:4b:03"
      cert_thumbprint     = "E201821E152D7AE86078C4E6A3A3A1E1C5E29F9A"
      cert_valid_from     = "2020-12-28"
      cert_valid_to       = "2021-12-28"

      country             = "RU"
      state               = "???"
      locality            = "Saint-Petersburg"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "59:a5:7e:8b:a3:dc:f2:b6:f5:99:81:fd:a1:4b:03"
      )
}
