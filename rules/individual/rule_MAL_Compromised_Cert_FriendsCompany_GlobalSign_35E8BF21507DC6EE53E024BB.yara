import "pe"

rule MAL_Compromised_Cert_FriendsCompany_GlobalSign_35E8BF21507DC6EE53E024BB {
   meta:
      description         = "Detects FriendsCompany with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-28"
      version             = "1.0"

      hash                = "dcdaeb418cf49503d788d9471a8d1f1f6124209aeb86cfe4d17631b1e1a92d73"
      malware             = "FriendsCompany"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "OOO WLD GROUPP"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "35:e8:bf:21:50:7d:c6:ee:53:e0:24:bb"
      cert_thumbprint     = "829FDFBCCFC4AAF1E25B2A3229B17ED793DAFD4B"
      cert_valid_from     = "2025-03-28"
      cert_valid_to       = "2026-03-29"

      country             = "RU"
      state               = "Saint Petersburg"
      locality            = "Saint Petersburg"
      email               = "wldgroupp@rambler.ru"
      rdn_serial_number   = "1167847423446"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "35:e8:bf:21:50:7d:c6:ee:53:e0:24:bb"
      )
}
