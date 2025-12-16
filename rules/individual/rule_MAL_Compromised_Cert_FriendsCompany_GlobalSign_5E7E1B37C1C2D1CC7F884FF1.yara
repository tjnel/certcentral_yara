import "pe"

rule MAL_Compromised_Cert_FriendsCompany_GlobalSign_5E7E1B37C1C2D1CC7F884FF1 {
   meta:
      description         = "Detects FriendsCompany with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-27"
      version             = "1.0"

      hash                = "2e33f42df7869fe19967ae9839d9346a976b13213e68e80a8611d71c864d8ba9"
      malware             = "FriendsCompany"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "Novadawn Technology Corporation"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "5e:7e:1b:37:c1:c2:d1:cc:7f:88:4f:f1"
      cert_thumbprint     = "212709cd8b881e416b395f4af827f60a491f15dc28781dadef543f711e27aeed"
      cert_valid_from     = "2025-01-27"
      cert_valid_to       = "2026-01-28"

      country             = "CA"
      state               = "Alberta"
      locality            = "Edmonton"
      email               = "???"
      rdn_serial_number   = "1261432-4"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "5e:7e:1b:37:c1:c2:d1:cc:7f:88:4f:f1"
      )
}
