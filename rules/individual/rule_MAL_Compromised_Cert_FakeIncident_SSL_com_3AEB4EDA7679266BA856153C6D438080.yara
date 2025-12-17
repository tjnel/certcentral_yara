import "pe"

rule MAL_Compromised_Cert_FakeIncident_SSL_com_3AEB4EDA7679266BA856153C6D438080 {
   meta:
      description         = "Detects FakeIncident with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-27"
      version             = "1.0"

      hash                = "6750134b7a676616fb461db84df4e0b3915203176cea64c256029f1df2b946ec"
      malware             = "FakeIncident"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "GeoTech-IT Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "3a:eb:4e:da:76:79:26:6b:a8:56:15:3c:6d:43:80:80"
      cert_thumbprint     = "B59E051A14321FBC632A343C8695E45295868881"
      cert_valid_from     = "2025-06-27"
      cert_valid_to       = "2026-06-26"

      country             = "FI"
      state               = "Varsinais-Suomi"
      locality            = "Raisio"
      email               = "???"
      rdn_serial_number   = "2678225-8"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "3a:eb:4e:da:76:79:26:6b:a8:56:15:3c:6d:43:80:80"
      )
}
