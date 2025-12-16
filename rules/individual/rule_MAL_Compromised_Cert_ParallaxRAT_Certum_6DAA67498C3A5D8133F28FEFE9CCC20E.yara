import "pe"

rule MAL_Compromised_Cert_ParallaxRAT_Certum_6DAA67498C3A5D8133F28FEFE9CCC20E {
   meta:
      description         = "Detects ParallaxRAT with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-09-21"
      version             = "1.0"

      hash                = "dae9032c305a447c81635cfae72e942b411b531c1892c943ac80fa0797b8dc05"
      malware             = "ParallaxRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "Rimsara Development OU"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "6d:aa:67:49:8c:3a:5d:81:33:f2:8f:ef:e9:cc:c2:0e"
      cert_thumbprint     = "0B7228ED2EB6FA002AAAC75896C15912D95AA08B"
      cert_valid_from     = "2023-09-21"
      cert_valid_to       = "2024-09-20"

      country             = "EE"
      state               = "Ida-Viru maakond"
      locality            = "Narva"
      email               = "???"
      rdn_serial_number   = "16807868"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "6d:aa:67:49:8c:3a:5d:81:33:f2:8f:ef:e9:cc:c2:0e"
      )
}
