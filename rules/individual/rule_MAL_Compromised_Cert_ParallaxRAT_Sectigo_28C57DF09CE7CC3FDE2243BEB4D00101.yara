import "pe"

rule MAL_Compromised_Cert_ParallaxRAT_Sectigo_28C57DF09CE7CC3FDE2243BEB4D00101 {
   meta:
      description         = "Detects ParallaxRAT with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-06-03"
      version             = "1.0"

      hash                = "88c109e8bca8a35c02efa6ce6f27bb714d16623382cd8181011e8776c5f017a5"
      malware             = "ParallaxRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "WATER, s.r.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "28:c5:7d:f0:9c:e7:cc:3f:de:22:43:be:b4:d0:01:01"
      cert_thumbprint     = "E8AF91EB205CBAEAD7F4D08DEB8AA776C075EB80"
      cert_valid_from     = "2021-06-03"
      cert_valid_to       = "2022-06-03"

      country             = "CZ"
      state               = "???"
      locality            = "Praha"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "28:c5:7d:f0:9c:e7:cc:3f:de:22:43:be:b4:d0:01:01"
      )
}
