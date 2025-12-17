import "pe"

rule MAL_Compromised_Cert_ParallaxRAT_Sectigo_0A5B4F67AD8B22AFC2DEBE6CE5F8F679 {
   meta:
      description         = "Detects ParallaxRAT with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-12-09"
      version             = "1.0"

      hash                = "723cb0067010b79e0cc780ea786fef8c6c17b68c383acc8183b2ae7332e95abf"
      malware             = "ParallaxRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "Farad LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "0a:5b:4f:67:ad:8b:22:af:c2:de:be:6c:e5:f8:f6:79"
      cert_thumbprint     = "1213865AF7DDAC1568830748DBDDA21498DFB0BA"
      cert_valid_from     = "2020-12-09"
      cert_valid_to       = "2021-12-09"

      country             = "RU"
      state               = "???"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "0a:5b:4f:67:ad:8b:22:af:c2:de:be:6c:e5:f8:f6:79"
      )
}
