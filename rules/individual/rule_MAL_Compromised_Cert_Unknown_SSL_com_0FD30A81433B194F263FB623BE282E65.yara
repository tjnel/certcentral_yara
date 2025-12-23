import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_0FD30A81433B194F263FB623BE282E65 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-10"
      version             = "1.0"

      hash                = "88954524b8e24acad13d00e1bb66f6cd437df1039087945ff1b010f9c217c1fa"
      malware             = "Unknown"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware was distributed as a fake invoice."

      signer              = "Contour Design Norge AS"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "0f:d3:0a:81:43:3b:19:4f:26:3f:b6:23:be:28:2e:65"
      cert_thumbprint     = "BFA93667BFA6D1F88EFFBA68073A76866403B29A"
      cert_valid_from     = "2025-12-10"
      cert_valid_to       = "2026-12-10"

      country             = "NO"
      state               = "Oslo"
      locality            = "Oslo"
      email               = "???"
      rdn_serial_number   = "988514241"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "0f:d3:0a:81:43:3b:19:4f:26:3f:b6:23:be:28:2e:65"
      )
}
