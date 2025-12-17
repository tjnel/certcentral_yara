import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_4D342A1C66BBC03F85A2CB9F1752E843 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-11"
      version             = "1.0"

      hash                = "98a8144cc73588295f749e521d89585dfcd74d808b3a010bc7bcb9def190a370"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "NATIONAL CARE CONSORTIUM LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "4d:34:2a:1c:66:bb:c0:3f:85:a2:cb:9f:17:52:e8:43"
      cert_thumbprint     = "49A0C82BE5047EE35E620F02D3B7D5616F17CE98"
      cert_valid_from     = "2024-12-11"
      cert_valid_to       = "2025-12-11"

      country             = "GB"
      state               = "???"
      locality            = "Nottingham"
      email               = "???"
      rdn_serial_number   = "10765210"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "4d:34:2a:1c:66:bb:c0:3f:85:a2:cb:9f:17:52:e8:43"
      )
}
