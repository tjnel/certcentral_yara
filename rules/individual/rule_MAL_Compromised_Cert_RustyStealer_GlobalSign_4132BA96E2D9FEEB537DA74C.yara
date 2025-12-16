import "pe"

rule MAL_Compromised_Cert_RustyStealer_GlobalSign_4132BA96E2D9FEEB537DA74C {
   meta:
      description         = "Detects RustyStealer with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-03"
      version             = "1.0"

      hash                = "31a8a2762b42a1fe4be2aed9d112a169f791bd86a85e68d738aea51312096442"
      malware             = "RustyStealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "FUTURICO LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "41:32:ba:96:e2:d9:fe:eb:53:7d:a7:4c"
      cert_thumbprint     = "CFF9E5FEE264DD58DBD6A3165322807248D3A1B2"
      cert_valid_from     = "2024-09-03"
      cert_valid_to       = "2025-09-04"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1247700385536"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "41:32:ba:96:e2:d9:fe:eb:53:7d:a7:4c"
      )
}
