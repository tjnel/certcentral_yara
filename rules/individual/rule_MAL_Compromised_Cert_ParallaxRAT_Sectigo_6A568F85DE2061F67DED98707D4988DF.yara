import "pe"

rule MAL_Compromised_Cert_ParallaxRAT_Sectigo_6A568F85DE2061F67DED98707D4988DF {
   meta:
      description         = "Detects ParallaxRAT with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-02-11"
      version             = "1.0"

      hash                = "6f8fc539952555b057adf7810aca782a29f8f624e1d46a0f4732db3763130725"
      malware             = "ParallaxRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "OOO Apladis"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "6a:56:8f:85:de:20:61:f6:7d:ed:98:70:7d:49:88:df"
      cert_thumbprint     = "ED7E16A65294086FBDEEE09C562B0722FDB2DB48"
      cert_valid_from     = "2021-02-11"
      cert_valid_to       = "2022-02-11"

      country             = "RU"
      state               = "???"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "6a:56:8f:85:de:20:61:f6:7d:ed:98:70:7d:49:88:df"
      )
}
