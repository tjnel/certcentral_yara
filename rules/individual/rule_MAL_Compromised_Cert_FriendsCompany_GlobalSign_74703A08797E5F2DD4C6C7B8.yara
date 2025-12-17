import "pe"

rule MAL_Compromised_Cert_FriendsCompany_GlobalSign_74703A08797E5F2DD4C6C7B8 {
   meta:
      description         = "Detects FriendsCompany with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-30"
      version             = "1.0"

      hash                = "b4b18e51c1a1545a9ab869db2ca12782aae89d835220295cd45acd287f02ab93"
      malware             = "FriendsCompany"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "RMB SYSTEM sp. z o. o."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "74:70:3a:08:79:7e:5f:2d:d4:c6:c7:b8"
      cert_thumbprint     = "2251345B20556D9E796DF3E042A1219F94CF5CF3"
      cert_valid_from     = "2025-01-30"
      cert_valid_to       = "2028-01-31"

      country             = "PL"
      state               = "Lubelskie"
      locality            = "Lublin"
      email               = "admin@rmb-system.com"
      rdn_serial_number   = "0000850938"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "74:70:3a:08:79:7e:5f:2d:d4:c6:c7:b8"
      )
}
