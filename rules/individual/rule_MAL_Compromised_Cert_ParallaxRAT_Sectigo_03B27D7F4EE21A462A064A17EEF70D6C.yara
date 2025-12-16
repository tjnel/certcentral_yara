import "pe"

rule MAL_Compromised_Cert_ParallaxRAT_Sectigo_03B27D7F4EE21A462A064A17EEF70D6C {
   meta:
      description         = "Detects ParallaxRAT with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-02-22"
      version             = "1.0"

      hash                = "7087214159114804bf5e751cee8004818f6d78d671c646ec0775fbc5b3954b10"
      malware             = "ParallaxRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "CCL TRADING LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "03:b2:7d:7f:4e:e2:1a:46:2a:06:4a:17:ee:f7:0d:6c"
      cert_thumbprint     = "A278B5C8A9798EE3B3299EC92A4AB618016628EE"
      cert_valid_from     = "2021-02-22"
      cert_valid_to       = "2022-02-22"

      country             = "GB"
      state               = "???"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "03:b2:7d:7f:4e:e2:1a:46:2a:06:4a:17:ee:f7:0d:6c"
      )
}
