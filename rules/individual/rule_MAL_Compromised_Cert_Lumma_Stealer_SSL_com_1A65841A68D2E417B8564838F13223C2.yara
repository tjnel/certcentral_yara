import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_SSL_com_1A65841A68D2E417B8564838F13223C2 {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-06"
      version             = "1.0"

      hash                = "1a833452a5cdde9002e4b25adfc3a46247fb8c578acb47a25eca5fe89570d748"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "Shanghai Songling Group Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "1a:65:84:1a:68:d2:e4:17:b8:56:48:38:f1:32:23:c2"
      cert_thumbprint     = "D3015AF4E20EDC894B6F23079959CF7B64D135A2"
      cert_valid_from     = "2024-08-06"
      cert_valid_to       = "2025-08-06"

      country             = "CN"
      state               = "???"
      locality            = "Shanghai"
      email               = "???"
      rdn_serial_number   = "9131010706253653XP"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "1a:65:84:1a:68:d2:e4:17:b8:56:48:38:f1:32:23:c2"
      )
}
