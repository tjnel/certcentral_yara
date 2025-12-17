import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_GlobalSign_70093AF339876742820D7941 {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-04"
      version             = "1.0"

      hash                = "cd207b81505f13d46d94b08fb5130ddae52bd1748856e6b474688e590933a718"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "AZALEA LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "70:09:3a:f3:39:87:67:42:82:0d:79:41"
      cert_thumbprint     = "686B7EBBA606303B5085633FCAA0685272B4D9B9"
      cert_valid_from     = "2024-12-04"
      cert_valid_to       = "2025-12-05"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1247700738108"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "70:09:3a:f3:39:87:67:42:82:0d:79:41"
      )
}
