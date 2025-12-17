import "pe"

rule MAL_Compromised_Cert_Wagmi_Traffer_Team_GlobalSign_407678F5814F5C443165FA66 {
   meta:
      description         = "Detects Wagmi Traffer Team with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-24"
      version             = "1.0"

      hash                = "A092E37CBFA79887D68BD1F485BD124A689F4DBAF065B91B3B298FB013531041"
      malware             = "Wagmi Traffer Team"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC Pik Harmony"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "40:76:78:f5:81:4f:5c:44:31:65:fa:66"
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
         sig.serial == "40:76:78:f5:81:4f:5c:44:31:65:fa:66"
      )
}
