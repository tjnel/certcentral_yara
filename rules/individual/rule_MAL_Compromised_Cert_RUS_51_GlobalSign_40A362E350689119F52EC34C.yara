import "pe"

rule MAL_Compromised_Cert_RUS_51_GlobalSign_40A362E350689119F52EC34C {
   meta:
      description         = "Detects RUS-51 with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-08"
      version             = "1.0"

      hash                = "1da91d2570329f9e214f51bc633283f10bd55a145b7b3d254e03175fd86292d9"
      malware             = "RUS-51"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "AM MISBAH Tech Inc."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "40:a3:62:e3:50:68:91:19:f5:2e:c3:4c"
      cert_thumbprint     = "80A9BC77CE11DA98E9E54F1E545C6C5B806C518A"
      cert_valid_from     = "2024-11-08"
      cert_valid_to       = "2025-11-09"

      country             = "CA"
      state               = "British Columbia"
      locality            = "Surrey"
      email               = "???"
      rdn_serial_number   = "13355462"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "40:a3:62:e3:50:68:91:19:f5:2e:c3:4c"
      )
}
