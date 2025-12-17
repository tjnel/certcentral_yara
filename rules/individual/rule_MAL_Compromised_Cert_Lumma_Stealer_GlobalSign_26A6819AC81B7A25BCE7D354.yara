import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_GlobalSign_26A6819AC81B7A25BCE7D354 {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-02-22"
      version             = "1.0"

      hash                = "97a586f21b94fe85d47179d0b6b55b86253754037274d37fad682a12bd8ef02c"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "MekoGuard Bytemin Information Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "26:a6:81:9a:c8:1b:7a:25:bc:e7:d3:54"
      cert_thumbprint     = "A53E2045C456BC5879E1159245884740FF0BE11D"
      cert_valid_from     = "2024-02-22"
      cert_valid_to       = "2025-02-06"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Foshan"
      email               = "???"
      rdn_serial_number   = "91440605MACR7QA22Q"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "26:a6:81:9a:c8:1b:7a:25:bc:e7:d3:54"
      )
}
