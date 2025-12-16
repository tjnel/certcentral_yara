import "pe"

rule MAL_Compromised_Cert_Latrodectus_SSL_com_63A1D220486892587186887E3B99011E {
   meta:
      description         = "Detects Latrodectus with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-17"
      version             = "1.0"

      hash                = "050d979457c9adfd500f480d8ea216fdc0c0b0781c59fa623e0d6ce832f5d13e"
      malware             = "Latrodectus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ECO BUILD HOUSE SP Z O O"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "63:a1:d2:20:48:68:92:58:71:86:88:7e:3b:99:01:1e"
      cert_thumbprint     = "1D30351CB18AE8DF3F3D8DCEF0AE4D7948FFA067"
      cert_valid_from     = "2025-04-17"
      cert_valid_to       = "2026-04-17"

      country             = "PL"
      state               = "Podlaskie Voivodeship"
      locality            = "Białystok"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "63:a1:d2:20:48:68:92:58:71:86:88:7e:3b:99:01:1e"
      )
}
