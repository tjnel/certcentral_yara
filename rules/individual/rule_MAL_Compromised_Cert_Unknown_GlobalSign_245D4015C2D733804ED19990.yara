import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_245D4015C2D733804ED19990 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-01"
      version             = "1.0"

      hash                = "10f102242e0171dec27e9372899e65e50dc5e8e78f2f22b271bcfb7a40499745"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC Yanex"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "24:5d:40:15:c2:d7:33:80:4e:d1:99:90"
      cert_thumbprint     = "B8D69D6100C184418E5A239E9FE9E11FD9796C9E"
      cert_valid_from     = "2025-10-01"
      cert_valid_to       = "2026-05-31"

      country             = "RU"
      state               = "Nizhny Novgorod Oblast"
      locality            = "Pochinki"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "24:5d:40:15:c2:d7:33:80:4e:d1:99:90"
      )
}
