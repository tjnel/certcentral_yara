import "pe"

rule MAL_Compromised_Cert_PDFusion_GlobalSign_538F0DC7777C4F5A602D8A14 {
   meta:
      description         = "Detects PDFusion with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-19"
      version             = "1.0"

      hash                = "90d9d441a92a3746b76657b3d95af6b25c125a196a4d2c0b6731241209428ea8"
      malware             = "PDFusion"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "KNAF TCHELET LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "53:8f:0d:c7:77:7c:4f:5a:60:2d:8a:14"
      cert_thumbprint     = "832B58B047B2424E684A9E792DFD02F5282CD467"
      cert_valid_from     = "2024-09-19"
      cert_valid_to       = "2025-09-20"

      country             = "IL"
      state               = "Tel Aviv"
      locality            = "Tel Aviv-Jaffa"
      email               = "support@knaftchelet.com"
      rdn_serial_number   = "516891132"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "53:8f:0d:c7:77:7c:4f:5a:60:2d:8a:14"
      )
}
