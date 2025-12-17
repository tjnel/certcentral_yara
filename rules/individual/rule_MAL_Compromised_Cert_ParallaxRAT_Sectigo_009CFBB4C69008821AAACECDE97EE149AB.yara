import "pe"

rule MAL_Compromised_Cert_ParallaxRAT_Sectigo_009CFBB4C69008821AAACECDE97EE149AB {
   meta:
      description         = "Detects ParallaxRAT with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-05-27"
      version             = "1.0"

      hash                = "bbe2a604c11442ee74adb7fa17910ca8e5665ab463e4a45b478707faa3a284e4"
      malware             = "ParallaxRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "Kivaliz Prest s.r.l."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:9c:fb:b4:c6:90:08:82:1a:aa:ce:cd:e9:7e:e1:49:ab"
      cert_thumbprint     = "0E392277EF97BF372F17ADDEF94BA14961E376B3"
      cert_valid_from     = "2020-05-27"
      cert_valid_to       = "2021-05-27"

      country             = "RO"
      state               = "Mures"
      locality            = "Livezeni"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:9c:fb:b4:c6:90:08:82:1a:aa:ce:cd:e9:7e:e1:49:ab"
      )
}
