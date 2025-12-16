import "pe"

rule MAL_Compromised_Cert_ParallaxRat_DigiCert_0883DB137021B51F3A2A08A76A4BC066 {
   meta:
      description         = "Detects ParallaxRat with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-07-28"
      version             = "1.0"

      hash                = "7220bd358f7a359fba4e076252af1c06eddf175463b32a03aa1d59b199c684de"
      malware             = "ParallaxRat"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "Divertida Creative Limited"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "08:83:db:13:70:21:b5:1f:3a:2a:08:a7:6a:4b:c0:66"
      cert_thumbprint     = "C049731B453AB96F0D81D02392C9FC57257E647D"
      cert_valid_from     = "2021-07-28"
      cert_valid_to       = "2022-07-27"

      country             = "IE"
      state               = "???"
      locality            = "Dublin"
      email               = "???"
      rdn_serial_number   = "700013"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "08:83:db:13:70:21:b5:1f:3a:2a:08:a7:6a:4b:c0:66"
      )
}
