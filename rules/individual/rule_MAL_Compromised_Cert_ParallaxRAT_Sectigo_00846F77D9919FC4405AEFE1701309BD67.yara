import "pe"

rule MAL_Compromised_Cert_ParallaxRAT_Sectigo_00846F77D9919FC4405AEFE1701309BD67 {
   meta:
      description         = "Detects ParallaxRAT with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-05-19"
      version             = "1.0"

      hash                = "8c6e507be687fd725cf66f3a4d405a43fc575a275024a5ed164e90b873fe447c"
      malware             = "ParallaxRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "IPM Skupina d.o.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:84:6f:77:d9:91:9f:c4:40:5a:ef:e1:70:13:09:bd:67"
      cert_thumbprint     = "FFDF8C9A92823B7198BDCBD4611A4087A5BE222D"
      cert_valid_from     = "2021-05-19"
      cert_valid_to       = "2022-05-19"

      country             = "SI"
      state               = "Ljubljana"
      locality            = "Ljubljana"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:84:6f:77:d9:91:9f:c4:40:5a:ef:e1:70:13:09:bd:67"
      )
}
