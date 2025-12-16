import "pe"

rule MAL_Compromised_Cert_FriendsCompany_GlobalSign_465457B019B7198ED0FCEE1B {
   meta:
      description         = "Detects FriendsCompany with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-16"
      version             = "1.0"

      hash                = "39308d995d17f7a91a766e9da0c925c021a005006f879f6d68b85aa1a333e90d"
      malware             = "FriendsCompany"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "Spparts Tech Inc."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "46:54:57:b0:19:b7:19:8e:d0:fc:ee:1b"
      cert_thumbprint     = "56395970d37aa8d7f2e9fc81390e52d133281ebab65d0e4b5bb8a5a531fdc1c5"
      cert_valid_from     = "2025-01-16"
      cert_valid_to       = "2026-01-17"

      country             = "CA"
      state               = "British Columbia"
      locality            = "Delta"
      email               = "???"
      rdn_serial_number   = "1450347-3"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "46:54:57:b0:19:b7:19:8e:d0:fc:ee:1b"
      )
}
