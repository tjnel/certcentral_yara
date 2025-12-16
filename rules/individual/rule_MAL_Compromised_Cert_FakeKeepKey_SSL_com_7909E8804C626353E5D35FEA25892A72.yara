import "pe"

rule MAL_Compromised_Cert_FakeKeepKey_SSL_com_7909E8804C626353E5D35FEA25892A72 {
   meta:
      description         = "Detects FakeKeepKey with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-25"
      version             = "1.0"

      hash                = "4592d64935081ae03564054fe64de80310dc44ae3e1e7899a004c6d6f6b1ef23"
      malware             = "FakeKeepKey"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "A-deal Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "79:09:e8:80:4c:62:63:53:e5:d3:5f:ea:25:89:2a:72"
      cert_thumbprint     = "C2781F59C5F18B4E5A4BCBC55CB429FDDE276091"
      cert_valid_from     = "2025-07-25"
      cert_valid_to       = "2026-07-25"

      country             = "FI"
      state               = "Varsinais-Suomi"
      locality            = "KARINAINEN"
      email               = "???"
      rdn_serial_number   = "3296686-2"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "79:09:e8:80:4c:62:63:53:e5:d3:5f:ea:25:89:2a:72"
      )
}
