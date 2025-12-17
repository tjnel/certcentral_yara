import "pe"

rule MAL_Compromised_Cert_FriendsCompany_GlobalSign_6610E8BAB06EBBA740ACA06A {
   meta:
      description         = "Detects FriendsCompany with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-18"
      version             = "1.0"

      hash                = "4bfd8b426224f863d39d8aba44920b2f93487d1de91d17b007df25195ebead6d"
      malware             = "FriendsCompany"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "MaKsimal GmbH"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "66:10:e8:ba:b0:6e:bb:a7:40:ac:a0:6a"
      cert_thumbprint     = "314EDC70D9CDA96D783DC80AC823A6014E70FA71"
      cert_valid_from     = "2025-02-18"
      cert_valid_to       = "2027-02-19"

      country             = "AT"
      state               = "Oberoesterreich"
      locality            = "Gunskirchen"
      email               = "admin@maksimalgmbh.com"
      rdn_serial_number   = "624953z"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "66:10:e8:ba:b0:6e:bb:a7:40:ac:a0:6a"
      )
}
