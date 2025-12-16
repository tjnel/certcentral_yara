import "pe"

rule MAL_Compromised_Cert_CrazyEvilTraffer_GlobalSign_02229C110CF8795398A98735 {
   meta:
      description         = "Detects CrazyEvilTraffer with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-03"
      version             = "1.0"

      hash                = "dce96f220fca15e105160d35cddb9022207da667c22a6607ea1f3249b0653287"
      malware             = "CrazyEvilTraffer"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "Olepole LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "02:22:9c:11:0c:f8:79:53:98:a9:87:35"
      cert_thumbprint     = "4026F7A5DA6ECDA8E5A2A676C9BF82D1AF2B57E9"
      cert_valid_from     = "2025-06-03"
      cert_valid_to       = "2026-06-04"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "02:22:9c:11:0c:f8:79:53:98:a9:87:35"
      )
}
