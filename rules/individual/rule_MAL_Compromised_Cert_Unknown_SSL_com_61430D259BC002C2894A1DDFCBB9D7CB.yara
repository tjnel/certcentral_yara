import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_61430D259BC002C2894A1DDFCBB9D7CB {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-10"
      version             = "1.0"

      hash                = "dc297aded70b0692ad0a24509e7bbec210bc0a1c7a105e99e1a8f76e3861ad34"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Just-Works ApS"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "61:43:0d:25:9b:c0:02:c2:89:4a:1d:df:cb:b9:d7:cb"
      cert_thumbprint     = "B6186819EF589837FFB19EA29D515F87CA75D315"
      cert_valid_from     = "2025-06-10"
      cert_valid_to       = "2026-06-10"

      country             = "DK"
      state               = "Capital Region of Denmark"
      locality            = "Kongens Lyngby"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "61:43:0d:25:9b:c0:02:c2:89:4a:1d:df:cb:b9:d7:cb"
      )
}
