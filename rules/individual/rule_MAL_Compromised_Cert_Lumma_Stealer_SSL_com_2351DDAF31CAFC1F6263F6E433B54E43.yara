import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_SSL_com_2351DDAF31CAFC1F6263F6E433B54E43 {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-25"
      version             = "1.0"

      hash                = "a4bb60772446f2cd2f7629574bbf5702c35ce2afcf6e4b3a3d157281cecc7234"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "Sichuan WCHX Technology Co., Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "23:51:dd:af:31:ca:fc:1f:62:63:f6:e4:33:b5:4e:43"
      cert_thumbprint     = "E29087AE930AC9BE77E22904EFE6416FE006F931"
      cert_valid_from     = "2024-08-25"
      cert_valid_to       = "2025-08-24"

      country             = "CN"
      state               = "Sichuan"
      locality            = "Chengdu"
      email               = "???"
      rdn_serial_number   = "91510100332110126P"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "23:51:dd:af:31:ca:fc:1f:62:63:f6:e4:33:b5:4e:43"
      )
}
