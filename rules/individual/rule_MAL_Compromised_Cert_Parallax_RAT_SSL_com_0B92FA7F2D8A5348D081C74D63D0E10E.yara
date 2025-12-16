import "pe"

rule MAL_Compromised_Cert_Parallax_RAT_SSL_com_0B92FA7F2D8A5348D081C74D63D0E10E {
   meta:
      description         = "Detects Parallax RAT with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-12"
      version             = "1.0"

      hash                = "be4cb40066c72827f2bf393b79c8b3f3cf135ae38cb33c919d3147d669d634a2"
      malware             = "Parallax RAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ALL-TECH LLC"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "0b:92:fa:7f:2d:8a:53:48:d0:81:c7:4d:63:d0:e1:0e"
      cert_thumbprint     = "3BBE32A7734B982264811E831228B163D0C26756"
      cert_valid_from     = "2024-12-12"
      cert_valid_to       = "2025-12-12"

      country             = "UA"
      state               = "???"
      locality            = "Poltava"
      email               = "???"
      rdn_serial_number   = "41260714"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "0b:92:fa:7f:2d:8a:53:48:d0:81:c7:4d:63:d0:e1:0e"
      )
}
