import "pe"

rule MAL_Compromised_Cert_ParallaxRAT_Sectigo_00D609B6C95428954A999A8A99D4F198AF {
   meta:
      description         = "Detects ParallaxRAT with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-02-09"
      version             = "1.0"

      hash                = "525d3b180847b425e376157caabbf860b421078903228d919d1e5e0fcce5741c"
      malware             = "ParallaxRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "OOO Fudl"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:d6:09:b6:c9:54:28:95:4a:99:9a:8a:99:d4:f1:98:af"
      cert_thumbprint     = "B1D8033DD7AD9E82674299FAED410817E42C4C40"
      cert_valid_from     = "2021-02-09"
      cert_valid_to       = "2022-02-09"

      country             = "RU"
      state               = "???"
      locality            = "Sankt-Peterburg"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:d6:09:b6:c9:54:28:95:4a:99:9a:8a:99:d4:f1:98:af"
      )
}
