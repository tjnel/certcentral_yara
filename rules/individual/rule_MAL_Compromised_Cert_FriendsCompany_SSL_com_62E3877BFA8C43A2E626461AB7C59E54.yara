import "pe"

rule MAL_Compromised_Cert_FriendsCompany_SSL_com_62E3877BFA8C43A2E626461AB7C59E54 {
   meta:
      description         = "Detects FriendsCompany with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-21"
      version             = "1.0"

      hash                = "0d7191500b429e6d258dc09807e52b59dd739c6636ce01ae945caf3170d49325"
      malware             = "FriendsCompany"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "Al-Base Trading Corp."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "62:e3:87:7b:fa:8c:43:a2:e6:26:46:1a:b7:c5:9e:54"
      cert_thumbprint     = "6CC45AD704EDDC34CCD008ED7D016E289AD25B0E"
      cert_valid_from     = "2025-05-21"
      cert_valid_to       = "2026-05-21"

      country             = "CA"
      state               = "British Columbia"
      locality            = "Surrey"
      email               = "???"
      rdn_serial_number   = "1119742-8"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "62:e3:87:7b:fa:8c:43:a2:e6:26:46:1a:b7:c5:9e:54"
      )
}
