import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_4E37AFBE047A0E2A0F268DDA {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-04"
      version             = "1.0"

      hash                = "d8a641a419044c45be2bf1bf10d143a5848a5c341935501664a007df73776bd7"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Hebei Leading Metals & Piping Industries Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "4e:37:af:be:04:7a:0e:2a:0f:26:8d:da"
      cert_thumbprint     = "466257DF743A67DCDA4C5624B55BC9B0CCD95815"
      cert_valid_from     = "2024-10-04"
      cert_valid_to       = "2025-10-05"

      country             = "CN"
      state               = "Hebei"
      locality            = "Shijiazhuang"
      email               = "???"
      rdn_serial_number   = "91130100320225946L"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "4e:37:af:be:04:7a:0e:2a:0f:26:8d:da"
      )
}
