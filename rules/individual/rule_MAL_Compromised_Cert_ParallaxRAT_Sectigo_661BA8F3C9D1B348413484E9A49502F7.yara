import "pe"

rule MAL_Compromised_Cert_ParallaxRAT_Sectigo_661BA8F3C9D1B348413484E9A49502F7 {
   meta:
      description         = "Detects ParallaxRAT with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-07-11"
      version             = "1.0"

      hash                = "ed5215be40b05fe324dfd185a741a48c604215482095e1953bfdad62725c8092"
      malware             = "ParallaxRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "Unique Digital Services Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "66:1b:a8:f3:c9:d1:b3:48:41:34:84:e9:a4:95:02:f7"
      cert_thumbprint     = "A7F7AFB9DD29EDE298EF1D941D0A34EB110F3CEC"
      cert_valid_from     = "2020-07-11"
      cert_valid_to       = "2021-07-11"

      country             = "CA"
      state               = "Alberta"
      locality            = "Calgary"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "66:1b:a8:f3:c9:d1:b3:48:41:34:84:e9:a4:95:02:f7"
      )
}
