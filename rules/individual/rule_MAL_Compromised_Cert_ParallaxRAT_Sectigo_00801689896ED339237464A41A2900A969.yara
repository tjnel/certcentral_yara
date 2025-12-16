import "pe"

rule MAL_Compromised_Cert_ParallaxRAT_Sectigo_00801689896ED339237464A41A2900A969 {
   meta:
      description         = "Detects ParallaxRAT with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-03-12"
      version             = "1.0"

      hash                = "ebf0083ad227764b7963171f0c2d156f56ad5a5835ce1a74e3c85b4902b04695"
      malware             = "ParallaxRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "GLG Rental ApS"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:80:16:89:89:6e:d3:39:23:74:64:a4:1a:29:00:a9:69"
      cert_thumbprint     = "9B0AB2E7F3514F6372D14B1F7F963C155B18BD24"
      cert_valid_from     = "2021-03-12"
      cert_valid_to       = "2022-03-12"

      country             = "DK"
      state               = "Nordjylland"
      locality            = "Farsø"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:80:16:89:89:6e:d3:39:23:74:64:a4:1a:29:00:a9:69"
      )
}
