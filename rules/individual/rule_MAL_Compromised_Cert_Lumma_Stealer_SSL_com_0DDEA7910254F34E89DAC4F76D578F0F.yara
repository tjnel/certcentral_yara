import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_SSL_com_0DDEA7910254F34E89DAC4F76D578F0F {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-20"
      version             = "1.0"

      hash                = "fe407790dad4c2b82a80548e5717a25994a35249209b94a2b13df894dca0a28a"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "BOTANICS BIOTECH LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "0d:de:a7:91:02:54:f3:4e:89:da:c4:f7:6d:57:8f:0f"
      cert_thumbprint     = "E588858D7C0B31955E9CD3E250A6D6274EAF895A"
      cert_valid_from     = "2024-11-20"
      cert_valid_to       = "2025-11-20"

      country             = "GB"
      state               = "???"
      locality            = "Edinburgh"
      email               = "???"
      rdn_serial_number   = "SC194382"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "0d:de:a7:91:02:54:f3:4e:89:da:c4:f7:6d:57:8f:0f"
      )
}
