import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_SSL_com_691C410E33DDF644086FA241107B646E {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-19"
      version             = "1.0"

      hash                = "f4350182d9a117138e47ce4622b3aa1ac9ebf2583f4932a6da78ea2ed7511a7f"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "Shanghai Yungpu Chemical Co., Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "69:1c:41:0e:33:dd:f6:44:08:6f:a2:41:10:7b:64:6e"
      cert_thumbprint     = "FDD829D3B46933EF8015B70B6C3FCE6BA9675578"
      cert_valid_from     = "2024-09-19"
      cert_valid_to       = "2025-09-19"

      country             = "CN"
      state               = "???"
      locality            = "Shanghai"
      email               = "???"
      rdn_serial_number   = "91310000570832845E"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "69:1c:41:0e:33:dd:f6:44:08:6f:a2:41:10:7b:64:6e"
      )
}
