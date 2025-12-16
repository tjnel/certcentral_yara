import "pe"

rule MAL_Compromised_Cert_FriendsCompany_GlobalSign_0D299A61BDA4BEAECBB27DC2 {
   meta:
      description         = "Detects FriendsCompany with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-07"
      version             = "1.0"

      hash                = "79881ec9356ca56c03ade331a2f8d08840c9fc4ef793edbf5d51ba1f2be89dd4"
      malware             = "FriendsCompany"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "CODE IN THE CONTEXT LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "0d:29:9a:61:bd:a4:be:ae:cb:b2:7d:c2"
      cert_thumbprint     = "D15225AFE5B409150D3F9B6D5FDB31F0CA7F8446"
      cert_valid_from     = "2025-02-07"
      cert_valid_to       = "2026-02-08"

      country             = "GB"
      state               = "Hampshire"
      locality            = "Winchester"
      email               = "???"
      rdn_serial_number   = "13628009"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "0d:29:9a:61:bd:a4:be:ae:cb:b2:7d:c2"
      )
}
