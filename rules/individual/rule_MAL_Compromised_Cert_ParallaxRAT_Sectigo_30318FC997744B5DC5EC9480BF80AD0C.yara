import "pe"

rule MAL_Compromised_Cert_ParallaxRAT_Sectigo_30318FC997744B5DC5EC9480BF80AD0C {
   meta:
      description         = "Detects ParallaxRAT with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-05-27"
      version             = "1.0"

      hash                = "dd2b6e5b02de97b7888bb22135c2c9771c6a2477a59e96463141c36d30e80fbb"
      malware             = "ParallaxRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "ZOMI INVEST, d.o.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "30:31:8f:c9:97:74:4b:5d:c5:ec:94:80:bf:80:ad:0c"
      cert_thumbprint     = "1ED0A44354A6E750B26594A0819CC0BBBAB16299"
      cert_valid_from     = "2021-05-27"
      cert_valid_to       = "2022-05-27"

      country             = "SI"
      state               = "???"
      locality            = "Trebnje"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "30:31:8f:c9:97:74:4b:5d:c5:ec:94:80:bf:80:ad:0c"
      )
}
