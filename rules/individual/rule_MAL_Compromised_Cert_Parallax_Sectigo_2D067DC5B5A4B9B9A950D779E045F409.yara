import "pe"

rule MAL_Compromised_Cert_Parallax_Sectigo_2D067DC5B5A4B9B9A950D779E045F409 {
   meta:
      description         = "Detects Parallax with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-16"
      version             = "1.0"

      hash                = "bf6f0db6beb6359e23103f4e4286ea0f81e495b1161ca5d167ea16c59367fbef"
      malware             = "Parallax"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "Wuhan Shuoxi Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "2d:06:7d:c5:b5:a4:b9:b9:a9:50:d7:79:e0:45:f4:09"
      cert_thumbprint     = "B8EE7EA2977BEAFDB0EF7977AFEFE210F9912938"
      cert_valid_from     = "2025-10-16"
      cert_valid_to       = "2026-10-16"

      country             = "CN"
      state               = "Hubei Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "2d:06:7d:c5:b5:a4:b9:b9:a9:50:d7:79:e0:45:f4:09"
      )
}
