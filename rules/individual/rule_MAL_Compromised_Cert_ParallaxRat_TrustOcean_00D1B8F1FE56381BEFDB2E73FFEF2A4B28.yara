import "pe"

rule MAL_Compromised_Cert_ParallaxRat_TrustOcean_00D1B8F1FE56381BEFDB2E73FFEF2A4B28 {
   meta:
      description         = "Detects ParallaxRat with compromised cert (TrustOcean)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-04-06"
      version             = "1.0"

      hash                = "6f522cc6adbe791575df40a518ba10c89cb54af0d849be0841b036b05d441fa9"
      malware             = "ParallaxRat"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "Seinäjoen Squash ja Bowling Oy"
      cert_issuer_short   = "TrustOcean"
      cert_issuer         = "TrustOcean Organization Software Vendor CA"
      cert_serial         = "00:d1:b8:f1:fe:56:38:1b:ef:db:2e:73:ff:ef:2a:4b:28"
      cert_thumbprint     = "350540A81922B63C31B3BE2D3B4E8BECE001726B"
      cert_valid_from     = "2021-04-06"
      cert_valid_to       = "2022-04-06"

      country             = "FI"
      state               = "???"
      locality            = "Seinäjoki"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "TrustOcean Organization Software Vendor CA" and
         sig.serial == "00:d1:b8:f1:fe:56:38:1b:ef:db:2e:73:ff:ef:2a:4b:28"
      )
}
