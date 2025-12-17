import "pe"

rule MAL_Compromised_Cert_Grandoreiro_GlobalSign_22AC324C723DA451B10246B7 {
   meta:
      description         = "Detects Grandoreiro with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-02-02"
      version             = "1.0"

      hash                = "34b7a7b91cc32dc8e86224c6d97bf50417d929e715288779ccdaa7375d6c4bb2"
      malware             = "Grandoreiro"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "AGE AND EXPERIENCE LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "22:ac:32:4c:72:3d:a4:51:b1:02:46:b7"
      cert_thumbprint     = "3327CC4AB5D1CF7AF8B2BFD22A6AA4B7C57CEE84"
      cert_valid_from     = "2024-02-02"
      cert_valid_to       = "2025-02-02"

      country             = "GB"
      state               = "North Yorkshire"
      locality            = "Harrogate"
      email               = "director@ageandexperiencelimited.com"
      rdn_serial_number   = "13772305"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "22:ac:32:4c:72:3d:a4:51:b1:02:46:b7"
      )
}
