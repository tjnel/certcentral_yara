import "pe"

rule MAL_Compromised_Cert_Wagmi_Traffer_Team_GlobalSign_34C5D23C18AC223122E893E5 {
   meta:
      description         = "Detects Wagmi Traffer Team with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-24"
      version             = "1.0"

      hash                = "CFFA1F0F88F5311AFC6AEDF2B19F1B24FDCA7E7CEB55FFDBC1428DF7B1191B2A"
      malware             = "Wagmi Traffer Team"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC Unitek"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "34:c5:d2:3c:18:ac:22:31:22:e8:93:e5"
      cert_thumbprint     = ""
      cert_valid_from     = "2025-04-24"
      cert_valid_to       = "2026-04-25"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = ""
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "34:c5:d2:3c:18:ac:22:31:22:e8:93:e5"
      )
}
