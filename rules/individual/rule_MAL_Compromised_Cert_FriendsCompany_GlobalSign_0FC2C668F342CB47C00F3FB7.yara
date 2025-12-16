import "pe"

rule MAL_Compromised_Cert_FriendsCompany_GlobalSign_0FC2C668F342CB47C00F3FB7 {
   meta:
      description         = "Detects FriendsCompany with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-12"
      version             = "1.0"

      hash                = "3beccc3a7df1ede9c5a0f5228b5028f719eab04d65321d7063f90e7c7d47e7f9"
      malware             = "FriendsCompany"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "AMPlus Power Inc."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "0f:c2:c6:68:f3:42:cb:47:c0:0f:3f:b7"
      cert_thumbprint     = "3EDBEB26B8C38172A6BF87CCD625D40B946E31B1"
      cert_valid_from     = "2025-02-12"
      cert_valid_to       = "2026-02-13"

      country             = "CA"
      state               = "Ontario"
      locality            = "Kingston"
      email               = "???"
      rdn_serial_number   = "10322601"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "0f:c2:c6:68:f3:42:cb:47:c0:0f:3f:b7"
      )
}
