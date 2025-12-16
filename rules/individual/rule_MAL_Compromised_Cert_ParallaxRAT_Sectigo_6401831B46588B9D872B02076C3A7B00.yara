import "pe"

rule MAL_Compromised_Cert_ParallaxRAT_Sectigo_6401831B46588B9D872B02076C3A7B00 {
   meta:
      description         = "Detects ParallaxRAT with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-03-12"
      version             = "1.0"

      hash                = "0cfa9021ddabb0a9f3306397234f3f19ce70da1082b4291bfe9477c974aebbec"
      malware             = "ParallaxRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "ACTIV GROUP ApS"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "64:01:83:1b:46:58:8b:9d:87:2b:02:07:6c:3a:7b:00"
      cert_thumbprint     = "19FC95AC815865E8B57C80ED21A22E2C0FECC1FF"
      cert_valid_from     = "2021-03-12"
      cert_valid_to       = "2022-03-12"

      country             = "DK"
      state               = "Sjælland"
      locality            = "Hvalsø"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "64:01:83:1b:46:58:8b:9d:87:2b:02:07:6c:3a:7b:00"
      )
}
