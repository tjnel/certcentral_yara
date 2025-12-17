import "pe"

rule MAL_Compromised_Cert_FriendsCompany_GlobalSign_5781E1DF1C57601541DC6FC9 {
   meta:
      description         = "Detects FriendsCompany with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-03"
      version             = "1.0"

      hash                = "bc71f58b2438a89e2cd189b8896a97b2436f091ab240861b84435afcdc3db746"
      malware             = "FriendsCompany"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "DRSSOFT INC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "57:81:e1:df:1c:57:60:15:41:dc:6f:c9"
      cert_thumbprint     = "d4ac34a8c9b1385bd3b6da3f8151dbca851209823ed329fa26c419e8d86d1cd7"
      cert_valid_from     = "2024-10-03"
      cert_valid_to       = "2025-10-04"

      country             = "US"
      state               = "Alabama"
      locality            = "Birmingham"
      email               = "???"
      rdn_serial_number   = "000-224-897"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "57:81:e1:df:1c:57:60:15:41:dc:6f:c9"
      )
}
