import "pe"

rule MAL_Compromised_Cert_FriendsCompany_GlobalSign_46CB25253979CA375FBDE978 {
   meta:
      description         = "Detects FriendsCompany with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-25"
      version             = "1.0"

      hash                = "d2a76bb92897eb6d0ec5d29661b07e3614390bca529b4f0542c1a260e5f94676"
      malware             = "FriendsCompany"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "CHANGE AGITATORS LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "46:cb:25:25:39:79:ca:37:5f:bd:e9:78"
      cert_thumbprint     = "167D3E3399C69CD324B650AC3B0C095C8E54507E"
      cert_valid_from     = "2025-02-25"
      cert_valid_to       = "2026-02-26"

      country             = "GB"
      state               = "Surrey"
      locality            = "Egham"
      email               = "???"
      rdn_serial_number   = "10684411"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "46:cb:25:25:39:79:ca:37:5f:bd:e9:78"
      )
}
