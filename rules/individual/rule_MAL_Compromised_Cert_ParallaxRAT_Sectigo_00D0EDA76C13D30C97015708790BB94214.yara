import "pe"

rule MAL_Compromised_Cert_ParallaxRAT_Sectigo_00D0EDA76C13D30C97015708790BB94214 {
   meta:
      description         = "Detects ParallaxRAT with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-04-23"
      version             = "1.0"

      hash                = "83afabd3bf44ba07ad9b09ffc85db8ea7ff0a32d888bd829e8733dcd2cd2779e"
      malware             = "ParallaxRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "LAEN ApS"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:d0:ed:a7:6c:13:d3:0c:97:01:57:08:79:0b:b9:42:14"
      cert_thumbprint     = "CB6DBEFC0949F7CC59BBDEEFFCA2F86D3CC8B630"
      cert_valid_from     = "2021-04-23"
      cert_valid_to       = "2022-04-23"

      country             = "DK"
      state               = "???"
      locality            = "Vallensbæk Strand"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:d0:ed:a7:6c:13:d3:0c:97:01:57:08:79:0b:b9:42:14"
      )
}
