import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_6E0368FFC87F26F9D13F4412AAA3E915 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-03-22"
      version             = "1.0"

      hash                = "ea18b965ab43d927a1d690f395f4e2b55a15db9744f68454a86b5508b302c404"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Just Add Water Italian Pizza Bread Pasta Mix Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "6e:03:68:ff:c8:7f:26:f9:d1:3f:44:12:aa:a3:e9:15"
      cert_thumbprint     = "164375B0C85F98E23533BC584F19FF514F74686B"
      cert_valid_from     = "2024-03-22"
      cert_valid_to       = "2025-03-22"

      country             = "CA"
      state               = "Alberta"
      locality            = "Calgary"
      email               = "???"
      rdn_serial_number   = "858926-7"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "6e:03:68:ff:c8:7f:26:f9:d1:3f:44:12:aa:a3:e9:15"
      )
}
