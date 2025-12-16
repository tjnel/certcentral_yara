import "pe"

rule MAL_Compromised_Cert_Winos_SSL_com_2C8C8943925A595FD69F063B98D83B1D {
   meta:
      description         = "Detects Winos with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-08"
      version             = "1.0"

      hash                = "7102e9a86b47b65aeebc1bef98abe0928388f122af98eb62bf61622a42303f67"
      malware             = "Winos"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Sid Narayanan Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "2c:8c:89:43:92:5a:59:5f:d6:9f:06:3b:98:d8:3b:1d"
      cert_thumbprint     = "FFAD91F59C7C87FD132FF491DDE1C4654AC5FFC8"
      cert_valid_from     = "2024-08-08"
      cert_valid_to       = "2025-08-07"

      country             = "GB"
      state               = "???"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "11953295"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "2c:8c:89:43:92:5a:59:5f:d6:9f:06:3b:98:d8:3b:1d"
      )
}
