import "pe"

rule MAL_Compromised_Cert_FriendsCompany_GlobalSign_4DBE694470C2449C1B460474 {
   meta:
      description         = "Detects FriendsCompany with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-14"
      version             = "1.0"

      hash                = "3333052fc4327ff35d8f6fbb74a7956e1f2586fe8c344d3b914eba0fd9e9cab0"
      malware             = "FriendsCompany"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "Jiangyin Fengyuan Electronics Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "4d:be:69:44:70:c2:44:9c:1b:46:04:74"
      cert_thumbprint     = "383293AA310249D98C6781F0749C873A7BA86B40"
      cert_valid_from     = "2025-03-14"
      cert_valid_to       = "2026-03-15"

      country             = "CN"
      state               = "Jiangsu"
      locality            = "Wuxi"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "4d:be:69:44:70:c2:44:9c:1b:46:04:74"
      )
}
