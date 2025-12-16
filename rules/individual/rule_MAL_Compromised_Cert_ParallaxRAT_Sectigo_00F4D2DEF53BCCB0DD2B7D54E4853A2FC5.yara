import "pe"

rule MAL_Compromised_Cert_ParallaxRAT_Sectigo_00F4D2DEF53BCCB0DD2B7D54E4853A2FC5 {
   meta:
      description         = "Detects ParallaxRAT with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-07-27"
      version             = "1.0"

      hash                = "138c60f8df9c59cf59cbdfbf5004ceda539b0de2cd70207b79833805594a9746"
      malware             = "ParallaxRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "PETROYL GROUP, TOV"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:f4:d2:de:f5:3b:cc:b0:dd:2b:7d:54:e4:85:3a:2f:c5"
      cert_thumbprint     = "3725EB9700D2761EAF52972972540F06E28F8053"
      cert_valid_from     = "2020-07-27"
      cert_valid_to       = "2021-07-27"

      country             = "UA"
      state               = "???"
      locality            = "Vinnytska region"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:f4:d2:de:f5:3b:cc:b0:dd:2b:7d:54:e4:85:3a:2f:c5"
      )
}
