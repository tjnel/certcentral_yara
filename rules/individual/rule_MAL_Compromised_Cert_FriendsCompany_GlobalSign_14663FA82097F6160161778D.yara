import "pe"

rule MAL_Compromised_Cert_FriendsCompany_GlobalSign_14663FA82097F6160161778D {
   meta:
      description         = "Detects FriendsCompany with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-07"
      version             = "1.0"

      hash                = "302c964d52de43ce0c11cbf2b90c277b159e8365233c732c675c0e16e748b39f"
      malware             = "FriendsCompany"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "PAT sp. z o. o."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "14:66:3f:a8:20:97:f6:16:01:61:77:8d"
      cert_thumbprint     = "F798FCA1BA2FD09E5B85B112D38C1F1ABD05E978"
      cert_valid_from     = "2025-02-07"
      cert_valid_to       = "2026-02-08"

      country             = "PL"
      state               = "Śląskie"
      locality            = "Gliwice"
      email               = "admin@patgliwice.com"
      rdn_serial_number   = "0000682928"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "14:66:3f:a8:20:97:f6:16:01:61:77:8d"
      )
}
