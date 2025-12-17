import "pe"

rule MAL_Compromised_Cert_FriendsCompany_SSL_com_151F088C6A9ADEF03457543A7C33BCD3 {
   meta:
      description         = "Detects FriendsCompany with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-10"
      version             = "1.0"

      hash                = "469734a8acf5f8adf7869abaf1958ba12373aa4434a9aae7b4232e497ba845a2"
      malware             = "FriendsCompany"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "JMD Event-Ticketing GmbH"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "15:1f:08:8c:6a:9a:de:f0:34:57:54:3a:7c:33:bc:d3"
      cert_thumbprint     = "016BE5A7939FBD817616404D12764A9235594737"
      cert_valid_from     = "2025-06-10"
      cert_valid_to       = "2026-06-10"

      country             = "AT"
      state               = "Vienna"
      locality            = "Vienna"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "15:1f:08:8c:6a:9a:de:f0:34:57:54:3a:7c:33:bc:d3"
      )
}
