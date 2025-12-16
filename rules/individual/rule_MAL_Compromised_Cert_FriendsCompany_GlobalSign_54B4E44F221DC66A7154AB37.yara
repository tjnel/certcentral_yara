import "pe"

rule MAL_Compromised_Cert_FriendsCompany_GlobalSign_54B4E44F221DC66A7154AB37 {
   meta:
      description         = "Detects FriendsCompany with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-18"
      version             = "1.0"

      hash                = "5cacb3149b25c9a6cc625ef37fafd4c9a4f0c40d3f09b702dcdf194d130475bc"
      malware             = "FriendsCompany"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "SAULE FARMACJA sp. z o. o."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "54:b4:e4:4f:22:1d:c6:6a:71:54:ab:37"
      cert_thumbprint     = "4A4571719FEAEE7B9F375FAA9795EBF8FEEA4B0B"
      cert_valid_from     = "2025-02-18"
      cert_valid_to       = "2026-02-19"

      country             = "PL"
      state               = "Wielkopolskie"
      locality            = "Skórzewo"
      email               = "admin@saulefarmacja.com"
      rdn_serial_number   = "0000678403"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "54:b4:e4:4f:22:1d:c6:6a:71:54:ab:37"
      )
}
