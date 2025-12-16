import "pe"

rule MAL_Compromised_Cert_StealC_SSL_com_3950CAACF6BC64F75CA24F8B294AD41B {
   meta:
      description         = "Detects StealC with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-03"
      version             = "1.0"

      hash                = "1044130f4116b9432b2e6046184687b57a1680c572e83da8f59899b3284997e2"
      malware             = "StealC"
      malware_type        = "Infostealer"
      malware_notes       = "A popular and customizable infostealler that can also function as a loader: https://blog.sekoia.io/stealc-a-copycat-of-vidar-and-raccoon-infostealers-gaining-in-popularity-part-1/"

      signer              = "Perito IT Consulting Inc."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "39:50:ca:ac:f6:bc:64:f7:5c:a2:4f:8b:29:4a:d4:1b"
      cert_thumbprint     = "0D9E698C56D039A2D41481A1473F84D39C294D7B"
      cert_valid_from     = "2025-09-03"
      cert_valid_to       = "2026-09-03"

      country             = "CA"
      state               = "Ontario"
      locality            = "Mississauga"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "39:50:ca:ac:f6:bc:64:f7:5c:a2:4f:8b:29:4a:d4:1b"
      )
}
