import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_7B6BE67DA4FA164E4659E78E {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-13"
      version             = "1.0"

      hash                = "e4bcf2d340d092c3fe306399a1e745403a9c6296aa9a56d48b596c53fbddd845"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "PEIDEI LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "7b:6b:e6:7d:a4:fa:16:4e:46:59:e7:8e"
      cert_thumbprint     = "CE491F0DA64F733C369973D01A90D16529B80AB8"
      cert_valid_from     = "2025-01-13"
      cert_valid_to       = "2026-01-14"

      country             = "KE"
      state               = "Nairobi"
      locality            = "Nairobi"
      email               = "casinollc007@gmail.com"
      rdn_serial_number   = "PVT-AAACXT8"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "7b:6b:e6:7d:a4:fa:16:4e:46:59:e7:8e"
      )
}
