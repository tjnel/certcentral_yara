import "pe"

rule MAL_Compromised_Cert_Vidar_GlobalSign_0C7587D68C99A69476474BCE {
   meta:
      description         = "Detects Vidar with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-12"
      version             = "1.0"

      hash                = "2a4e132a12ae88be1acc1f6b3541464138e9737b80281d5e7dc2e91e001a2132"
      malware             = "Vidar"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "JDS RENT AND SALES SIA"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "0c:75:87:d6:8c:99:a6:94:76:47:4b:ce"
      cert_thumbprint     = "11B769ED46CECACA421445FE91ADCDBBE606AC0B"
      cert_valid_from     = "2025-12-12"
      cert_valid_to       = "2026-12-13"

      country             = "LV"
      state               = "Jelgava"
      locality            = "Jelgava"
      email               = "???"
      rdn_serial_number   = "40203563132"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "0c:75:87:d6:8c:99:a6:94:76:47:4b:ce"
      )
}
