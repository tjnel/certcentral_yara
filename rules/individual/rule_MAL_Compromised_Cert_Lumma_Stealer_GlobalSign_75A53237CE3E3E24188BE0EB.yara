import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_GlobalSign_75A53237CE3E3E24188BE0EB {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-30"
      version             = "1.0"

      hash                = "6ce21227a90c06234469aef5fa7173d5428ce0a69283a1dcd5c72168e4f7eda7"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "Nanning Fumei Electronic Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "75:a5:32:37:ce:3e:3e:24:18:8b:e0:eb"
      cert_thumbprint     = "CD8A623B3A7BCA36FB52C24F0CA4BC9DF5FDE685"
      cert_valid_from     = "2024-05-30"
      cert_valid_to       = "2025-05-31"

      country             = "CN"
      state               = "Guangxi"
      locality            = "Nanning"
      email               = "???"
      rdn_serial_number   = "91450100672491172H"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "75:a5:32:37:ce:3e:3e:24:18:8b:e0:eb"
      )
}
