import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_GlobalSign_1B1339DC9E5B26B1DD81255A {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-11"
      version             = "1.0"

      hash                = "2f01809f78d096e770544c434b5bb63b3a0461559f7dd98a25a04bf66c8784f4"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "P2Soft Inc."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "1b:13:39:dc:9e:5b:26:b1:dd:81:25:5a"
      cert_thumbprint     = "63D85A92367C766320FA038F4A9D474E0DE83119"
      cert_valid_from     = "2024-09-11"
      cert_valid_to       = "2025-09-12"

      country             = "CA"
      state               = "Ontario"
      locality            = "Ottawa"
      email               = "???"
      rdn_serial_number   = "13224384"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "1b:13:39:dc:9e:5b:26:b1:dd:81:25:5a"
      )
}
