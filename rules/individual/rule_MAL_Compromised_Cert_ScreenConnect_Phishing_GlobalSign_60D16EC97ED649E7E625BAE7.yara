import "pe"

rule MAL_Compromised_Cert_ScreenConnect_Phishing_GlobalSign_60D16EC97ED649E7E625BAE7 {
   meta:
      description         = "Detects ScreenConnect Phishing with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-04"
      version             = "1.0"

      hash                = "d651a7fd457ea621020c81b58a4b2fb35ddeb7eb06237d31d49314150ad9f88a"
      malware             = "ScreenConnect Phishing"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "BUSHMAN AND CERRITO, PLLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "60:d1:6e:c9:7e:d6:49:e7:e6:25:ba:e7"
      cert_thumbprint     = "B3186D5A2AC2617FAA23C8B0D187649C71FCDAE8"
      cert_valid_from     = "2025-08-04"
      cert_valid_to       = "2026-08-05"

      country             = "US"
      state               = "Michigan"
      locality            = "Farmington Hills"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "60:d1:6e:c9:7e:d6:49:e7:e6:25:ba:e7"
      )
}
