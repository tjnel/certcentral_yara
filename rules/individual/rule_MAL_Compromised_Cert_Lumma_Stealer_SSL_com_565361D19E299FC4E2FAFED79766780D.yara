import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_SSL_com_565361D19E299FC4E2FAFED79766780D {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-05"
      version             = "1.0"

      hash                = "1577ac7107e3034ca42af1f9549c15103c51b019e883c6967247d403a42cd0df"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "Atgor Investment Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "56:53:61:d1:9e:29:9f:c4:e2:fa:fe:d7:97:66:78:0d"
      cert_thumbprint     = "0A217E59F0C11473E187249F337B58A03F5B95DF"
      cert_valid_from     = "2024-09-05"
      cert_valid_to       = "2025-09-05"

      country             = "GB"
      state               = "???"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "08979969"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "56:53:61:d1:9e:29:9f:c4:e2:fa:fe:d7:97:66:78:0d"
      )
}
