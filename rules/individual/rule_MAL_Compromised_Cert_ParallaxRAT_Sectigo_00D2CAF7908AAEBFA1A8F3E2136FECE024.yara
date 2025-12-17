import "pe"

rule MAL_Compromised_Cert_ParallaxRAT_Sectigo_00D2CAF7908AAEBFA1A8F3E2136FECE024 {
   meta:
      description         = "Detects ParallaxRAT with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-08-26"
      version             = "1.0"

      hash                = "f7bab5e7e4487b86dd052dc4e9b9fd27f53d1a33852f6e5ce9ae91c302c33bcf"
      malware             = "ParallaxRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "FANATOR, OOO"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:d2:ca:f7:90:8a:ae:bf:a1:a8:f3:e2:13:6f:ec:e0:24"
      cert_thumbprint     = "629EDB30A50E365794D08E87217CB8CC324854AE"
      cert_valid_from     = "2020-08-26"
      cert_valid_to       = "2021-08-26"

      country             = "RU"
      state               = "???"
      locality            = "Volgograd"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:d2:ca:f7:90:8a:ae:bf:a1:a8:f3:e2:13:6f:ec:e0:24"
      )
}
