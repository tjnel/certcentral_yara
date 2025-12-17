import "pe"

rule MAL_Compromised_Cert_Bumblebee_GlobalSign_3805DC7EA4CD84151C90FFAF {
   meta:
      description         = "Detects Bumblebee with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-27"
      version             = "1.0"

      hash                = "cd454d80b75cbd4b23f9ec4a3e5746e53552f5a2a30c3ea1d5d3215cf41484aa"
      malware             = "Bumblebee"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC Resource+"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "38:05:dc:7e:a4:cd:84:15:1c:90:ff:af"
      cert_thumbprint     = "643F275F8E589AFCF4E2F6B4CB869066EABD2CD5"
      cert_valid_from     = "2025-05-27"
      cert_valid_to       = "2026-05-28"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1237700731806"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "38:05:dc:7e:a4:cd:84:15:1c:90:ff:af"
      )
}
