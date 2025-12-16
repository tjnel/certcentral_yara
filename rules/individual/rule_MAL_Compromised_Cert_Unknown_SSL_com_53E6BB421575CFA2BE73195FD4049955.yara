import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_53E6BB421575CFA2BE73195FD4049955 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-30"
      version             = "1.0"

      hash                = "98ecdcc1c1f723f38bbbb3f33d870dea34eaeb2e832a6a88618104406057da51"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "CAPELLO MEDIA SOLUTIONS LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "53:e6:bb:42:15:75:cf:a2:be:73:19:5f:d4:04:99:55"
      cert_thumbprint     = "AFA4DBE5B098717A926F7A28C100E87C9788BBDF"
      cert_valid_from     = "2025-06-30"
      cert_valid_to       = "2026-06-30"

      country             = "GB"
      state               = "???"
      locality            = "ALTRINCHAM"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "53:e6:bb:42:15:75:cf:a2:be:73:19:5f:d4:04:99:55"
      )
}
