import "pe"

rule MAL_Compromised_Cert_ParallaxRAT_Sectigo_00D1737E5A94D2AFF121163DF177ED7CF7 {
   meta:
      description         = "Detects ParallaxRAT with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-05-28"
      version             = "1.0"

      hash                = "66dfb7c408d734edc2967d50244babae27e4268ea93aa0daa5e6bbace607024c"
      malware             = "ParallaxRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "BedstSammen ApS"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:d1:73:7e:5a:94:d2:af:f1:21:16:3d:f1:77:ed:7c:f7"
      cert_thumbprint     = "ED2E4F72E8CB9B008A28B31DE440F024381E4C8D"
      cert_valid_from     = "2021-05-28"
      cert_valid_to       = "2022-05-28"

      country             = "DK"
      state               = "???"
      locality            = "Søborg"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:d1:73:7e:5a:94:d2:af:f1:21:16:3d:f1:77:ed:7c:f7"
      )
}
