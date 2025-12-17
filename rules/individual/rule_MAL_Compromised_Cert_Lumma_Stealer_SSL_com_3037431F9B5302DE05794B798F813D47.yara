import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_SSL_com_3037431F9B5302DE05794B798F813D47 {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-29"
      version             = "1.0"

      hash                = "b4629a833620ed96e6a15518ea9c5a22291255cc32e149c5b500e4b9ad7049ac"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "Allanson Consulting Limited"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "30:37:43:1f:9b:53:02:de:05:79:4b:79:8f:81:3d:47"
      cert_thumbprint     = "D90410465A569F2A537C9851049413CD08FB33AB"
      cert_valid_from     = "2024-07-29"
      cert_valid_to       = "2025-07-29"

      country             = "GB"
      state               = "England"
      locality            = "Manchester"
      email               = "???"
      rdn_serial_number   = "09418564"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "30:37:43:1f:9b:53:02:de:05:79:4b:79:8f:81:3d:47"
      )
}
