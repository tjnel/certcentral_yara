import "pe"

rule MAL_Compromised_Cert_RustyStealer_GlobalSign_6447DE04ACBF7F648E82D18D {
   meta:
      description         = "Detects RustyStealer with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-09"
      version             = "1.0"

      hash                = "41a83781c26f0f875faffbc013fbf74c0c7e6b63dccb194e2f486fb8619dd76c"
      malware             = "RustyStealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "FUJI FURUKAWA E&C (VIETNAM) CO.,LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "64:47:de:04:ac:bf:7f:64:8e:82:d1:8d"
      cert_thumbprint     = "05AF075F792DA8DA1A2E6CC72CAA93ED8C533029"
      cert_valid_from     = "2024-10-09"
      cert_valid_to       = "2025-10-10"

      country             = "VN"
      state               = "Ha Noi"
      locality            = "Ha Noi"
      email               = "quaysangkk231@gmail.com"
      rdn_serial_number   = "0300569478"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "64:47:de:04:ac:bf:7f:64:8e:82:d1:8d"
      )
}
