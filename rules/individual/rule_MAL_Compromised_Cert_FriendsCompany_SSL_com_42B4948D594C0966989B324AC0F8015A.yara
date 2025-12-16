import "pe"

rule MAL_Compromised_Cert_FriendsCompany_SSL_com_42B4948D594C0966989B324AC0F8015A {
   meta:
      description         = "Detects FriendsCompany with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-26"
      version             = "1.0"

      hash                = "791f3cb7b0f04be9491ee0aef75d9365bfc4242d0d630b86c6b57cf098a758af"
      malware             = "FriendsCompany"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "FarmWarp ApS"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "42:b4:94:8d:59:4c:09:66:98:9b:32:4a:c0:f8:01:5a"
      cert_thumbprint     = "F23D9571080AF674C1D31DEBE81D270A58908034"
      cert_valid_from     = "2025-02-26"
      cert_valid_to       = "2026-02-26"

      country             = "DK"
      state               = "Capital Region of Denmark"
      locality            = "Nivå"
      email               = "???"
      rdn_serial_number   = "42530425"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "42:b4:94:8d:59:4c:09:66:98:9b:32:4a:c0:f8:01:5a"
      )
}
