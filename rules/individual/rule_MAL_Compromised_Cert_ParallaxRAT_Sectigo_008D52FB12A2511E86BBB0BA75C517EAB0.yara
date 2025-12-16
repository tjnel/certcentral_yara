import "pe"

rule MAL_Compromised_Cert_ParallaxRAT_Sectigo_008D52FB12A2511E86BBB0BA75C517EAB0 {
   meta:
      description         = "Detects ParallaxRAT with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-09-04"
      version             = "1.0"

      hash                = "6b4db883cf4c04eedb117c22ea5adf581c76a1ceff8ace962182866f91587120"
      malware             = "ParallaxRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "VThink Software Consulting Inc."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:8d:52:fb:12:a2:51:1e:86:bb:b0:ba:75:c5:17:ea:b0"
      cert_thumbprint     = "A7425B343917A65DB27268B8FEA5D6D4FD482F76"
      cert_valid_from     = "2020-09-04"
      cert_valid_to       = "2021-09-04"

      country             = "CA"
      state               = "Ontario"
      locality            = "Orangeville"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:8d:52:fb:12:a2:51:1e:86:bb:b0:ba:75:c5:17:ea:b0"
      )
}
