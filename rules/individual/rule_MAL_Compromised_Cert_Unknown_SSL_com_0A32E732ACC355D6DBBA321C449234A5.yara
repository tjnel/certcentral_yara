import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_0A32E732ACC355D6DBBA321C449234A5 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-18"
      version             = "1.0"

      hash                = "ff80708b33b1b5b55e810bff263730b9f1de5fb83906bc74fd9a229776716a58"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Code2One Holding ApS"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "0a:32:e7:32:ac:c3:55:d6:db:ba:32:1c:44:92:34:a5"
      cert_thumbprint     = "D222C270D11F56674AD1775A741966CA312CC2DC"
      cert_valid_from     = "2025-04-18"
      cert_valid_to       = "2026-04-18"

      country             = "DK"
      state               = "Capital Region of Denmark"
      locality            = "Værløse"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "0a:32:e7:32:ac:c3:55:d6:db:ba:32:1c:44:92:34:a5"
      )
}
