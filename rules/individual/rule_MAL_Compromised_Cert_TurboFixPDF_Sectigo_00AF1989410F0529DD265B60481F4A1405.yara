import "pe"

rule MAL_Compromised_Cert_TurboFixPDF_Sectigo_00AF1989410F0529DD265B60481F4A1405 {
   meta:
      description         = "Detects TurboFixPDF with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-19"
      version             = "1.0"

      hash                = "d799cc1713932e9748ec9d293f831d150e1e345c0e58279cd7c3e49c35e667be"
      malware             = "TurboFixPDF"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "DataX Engine LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:af:19:89:41:0f:05:29:dd:26:5b:60:48:1f:4a:14:05"
      cert_thumbprint     = "2DF81AB14A5794F22722983AB3D8E8D7D643908B"
      cert_valid_from     = "2024-07-19"
      cert_valid_to       = "2025-07-19"

      country             = "US"
      state               = "Delaware"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:af:19:89:41:0f:05:29:dd:26:5b:60:48:1f:4a:14:05"
      )
}
