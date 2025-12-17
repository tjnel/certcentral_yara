import "pe"

rule MAL_Compromised_Cert_FriendsCompany_GlobalSign_0A824CC64D7CA10842746047 {
   meta:
      description         = "Detects FriendsCompany with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-13"
      version             = "1.0"

      hash                = "7200d36264736d7fc359ad02b0ee625d964b71e058b034f9e014f13925138065"
      malware             = "FriendsCompany"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "NATIONAL CLOUD COMPUTING Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "0a:82:4c:c6:4d:7c:a1:08:42:74:60:47"
      cert_thumbprint     = "44C1D4B9671CD0A75DE19877FE906231D880F5D4"
      cert_valid_from     = "2024-12-13"
      cert_valid_to       = "2025-12-14"

      country             = "CA"
      state               = "Ontario"
      locality            = "Toronto"
      email               = "???"
      rdn_serial_number   = "923966-9"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "0a:82:4c:c6:4d:7c:a1:08:42:74:60:47"
      )
}
