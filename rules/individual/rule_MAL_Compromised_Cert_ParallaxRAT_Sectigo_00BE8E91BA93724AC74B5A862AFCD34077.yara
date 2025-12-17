import "pe"

rule MAL_Compromised_Cert_ParallaxRAT_Sectigo_00BE8E91BA93724AC74B5A862AFCD34077 {
   meta:
      description         = "Detects ParallaxRAT with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-05-19"
      version             = "1.0"

      hash                = "9ccce653cb66833e9396151f5bc65f6c2744d955a9eaedad81eccd3da252803e"
      malware             = "ParallaxRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "A-LINE PIPE TOOLS INC."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:be:8e:91:ba:93:72:4a:c7:4b:5a:86:2a:fc:d3:40:77"
      cert_thumbprint     = "B0BF883E29C245A68D4861D8C50CFC75DCADC669"
      cert_valid_from     = "2021-05-19"
      cert_valid_to       = "2022-05-19"

      country             = "CA"
      state               = "Ontario"
      locality            = "THUNDER BAY"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:be:8e:91:ba:93:72:4a:c7:4b:5a:86:2a:fc:d3:40:77"
      )
}
