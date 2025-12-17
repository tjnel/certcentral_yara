import "pe"

rule MAL_Compromised_Cert_FriendsCompany_GlobalSign_5E6E10ECD4AE2EDCFE85605C {
   meta:
      description         = "Detects FriendsCompany with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-21"
      version             = "1.0"

      hash                = "8c997741843c505e816705b7d6e7db178c5bc8325892a1687506b59fb2ab2534"
      malware             = "FriendsCompany"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "GAME CHANGERS EXECUTIVE LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "5e:6e:10:ec:d4:ae:2e:dc:fe:85:60:5c"
      cert_thumbprint     = "9B36F7F59239008A07CDC70480A66753EFFC93FF"
      cert_valid_from     = "2025-02-21"
      cert_valid_to       = "2026-02-22"

      country             = "GB"
      state               = "London"
      locality            = "London"
      email               = "admin@gamechangersexecutive.com"
      rdn_serial_number   = "10976088"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "5e:6e:10:ec:d4:ae:2e:dc:fe:85:60:5c"
      )
}
