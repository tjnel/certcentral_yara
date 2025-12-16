import "pe"

rule MAL_Compromised_Cert_FriendsCompany_GlobalSign_41F26F261D5FE0453BCB27DD {
   meta:
      description         = "Detects FriendsCompany with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-05"
      version             = "1.0"

      hash                = "b6fb38d6d17d1bafe423677ed9372e8caebb7237d6d4cf1ec25c0990ed2b7a2a"
      malware             = "FriendsCompany"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "Concept LDL Inc."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "41:f2:6f:26:1d:5f:e0:45:3b:cb:27:dd"
      cert_thumbprint     = "7337ACC592D8725767DED2E94C579C120A531EB5"
      cert_valid_from     = "2025-02-05"
      cert_valid_to       = "2026-02-06"

      country             = "CA"
      state               = "Quebec"
      locality            = "Varennes"
      email               = "???"
      rdn_serial_number   = "954346-5"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "41:f2:6f:26:1d:5f:e0:45:3b:cb:27:dd"
      )
}
