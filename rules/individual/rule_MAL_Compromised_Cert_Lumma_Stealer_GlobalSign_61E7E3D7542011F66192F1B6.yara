import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_GlobalSign_61E7E3D7542011F66192F1B6 {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-27"
      version             = "1.0"

      hash                = "e239b11ecd605504a33038398cee8cb28bb2b4efff19401e7f5b954035a1cfa3"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "PTXGROUP VIETNAM COMPANY LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "61:e7:e3:d7:54:20:11:f6:61:92:f1:b6"
      cert_thumbprint     = "2069BFF0AC884C2D7EAC0FD6E9BB06F0649FF32A"
      cert_valid_from     = "2024-06-27"
      cert_valid_to       = "2025-06-28"

      country             = "VN"
      state               = "Ho Chi Minh"
      locality            = "Ho Chi Minh"
      email               = "???"
      rdn_serial_number   = "0313953441"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "61:e7:e3:d7:54:20:11:f6:61:92:f1:b6"
      )
}
