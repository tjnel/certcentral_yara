import "pe"

rule MAL_Compromised_Cert_Shadowladder_SSL_com_0E02FA85AB77FE9E40A12927E5994951 {
   meta:
      description         = "Detects Shadowladder with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-21"
      version             = "1.0"

      hash                = "591ffe7ef58214b0b82d5d68930d7c0efc68048fb97ac05c069969a6f3b2830e"
      malware             = "Shadowladder"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "JVR-Soft Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "0e:02:fa:85:ab:77:fe:9e:40:a1:29:27:e5:99:49:51"
      cert_thumbprint     = "7D0830A1C4C3400A18F02DE48F7472B04752075C"
      cert_valid_from     = "2025-05-21"
      cert_valid_to       = "2026-05-21"

      country             = "FI"
      state               = "Etelä-Pohjanmaa"
      locality            = "Hyllykallio"
      email               = "???"
      rdn_serial_number   = "1014971-4"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "0e:02:fa:85:ab:77:fe:9e:40:a1:29:27:e5:99:49:51"
      )
}
