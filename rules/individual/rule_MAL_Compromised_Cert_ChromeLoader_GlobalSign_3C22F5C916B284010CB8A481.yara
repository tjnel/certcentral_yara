import "pe"

rule MAL_Compromised_Cert_ChromeLoader_GlobalSign_3C22F5C916B284010CB8A481 {
   meta:
      description         = "Detects ChromeLoader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-03-22"
      version             = "1.0"

      hash                = "d158f3cfb47665928c5d304495fa99050a9e4c5b8d54332d400eec78bd7f98b6"
      malware             = "ChromeLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SOFTWARE ABFG LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "3c:22:f5:c9:16:b2:84:01:0c:b8:a4:81"
      cert_thumbprint     = "EE81E7D510B97695351EF3F2E0C10F4D0601EDA6"
      cert_valid_from     = "2023-03-22"
      cert_valid_to       = "2024-03-22"

      country             = "GB"
      state               = "London"
      locality            = "Ruislip"
      email               = "???"
      rdn_serial_number   = "14698890"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "3c:22:f5:c9:16:b2:84:01:0c:b8:a4:81"
      )
}
