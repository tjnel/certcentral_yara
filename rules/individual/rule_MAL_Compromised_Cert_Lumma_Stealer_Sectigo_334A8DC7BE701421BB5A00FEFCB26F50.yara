import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_Sectigo_334A8DC7BE701421BB5A00FEFCB26F50 {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-23"
      version             = "1.0"

      hash                = "1a0b974102462f42d51ae78898fa59bcb9e399c9c3207d26ce0a503a1262f1e6"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "袁州区创新探索网络工作室（个体工商户）"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "33:4a:8d:c7:be:70:14:21:bb:5a:00:fe:fc:b2:6f:50"
      cert_thumbprint     = "CBF33B2C384509341A4D74C25B332DF2DF82B494"
      cert_valid_from     = "2024-10-23"
      cert_valid_to       = "2025-10-23"

      country             = "CN"
      state               = "江西省"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "92360902MADYXP3F14"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "33:4a:8d:c7:be:70:14:21:bb:5a:00:fe:fc:b2:6f:50"
      )
}
