import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_GlobalSign_01F2C6C363767056ABD80E9C {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-12"
      version             = "1.0"

      hash                = "dc8e5cae55181833fa9f3dd0f9af37a2112620fd47b22e2fd9b4a1b05c68620f"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "TVAIS LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "01:f2:c6:c3:63:76:70:56:ab:d8:0e:9c"
      cert_thumbprint     = "74DF2582AF3780D81A8071E260C2B04259EFC35A"
      cert_valid_from     = "2024-12-12"
      cert_valid_to       = "2025-12-03"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1247700738383"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "01:f2:c6:c3:63:76:70:56:ab:d8:0e:9c"
      )
}
