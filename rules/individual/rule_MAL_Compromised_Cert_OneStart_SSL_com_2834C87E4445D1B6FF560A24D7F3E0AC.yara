import "pe"

rule MAL_Compromised_Cert_OneStart_SSL_com_2834C87E4445D1B6FF560A24D7F3E0AC {
   meta:
      description         = "Detects OneStart with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-06"
      version             = "1.0"

      hash                = "058a6c5a7dd6037265cc8a756d6b04bad9fb11b040560db159bc6125372a0001"
      malware             = "OneStart"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Onestart Technologies LLC"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "28:34:c8:7e:44:45:d1:b6:ff:56:0a:24:d7:f3:e0:ac"
      cert_thumbprint     = "AD2349D7E79F21E3BC073DCB79B4D7ED38BAB7A8"
      cert_valid_from     = "2025-03-06"
      cert_valid_to       = "2026-03-06"

      country             = "US"
      state               = "Delaware"
      locality            = "Dover"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "28:34:c8:7e:44:45:d1:b6:ff:56:0a:24:d7:f3:e0:ac"
      )
}
