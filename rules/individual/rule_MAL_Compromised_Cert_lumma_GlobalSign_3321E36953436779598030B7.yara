import "pe"

rule MAL_Compromised_Cert_lumma_GlobalSign_3321E36953436779598030B7 {
   meta:
      description         = "Detects lumma with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-26"
      version             = "1.0"

      hash                = "ac52dc2ae20931a9117b10a357331b88ac7533b2f1531b845019e5ccf0e18cde"
      malware             = "lumma"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "Ascension Design Inc."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "33:21:e3:69:53:43:67:79:59:80:30:b7"
      cert_thumbprint     = "c208820b6e60609cca87a87517fd9eca51597dac52d5e7829f684087bf39a8f1"
      cert_valid_from     = "2024-12-26"
      cert_valid_to       = "2025-12-27"

      country             = "CA"
      state               = "Ontario"
      locality            = "Ottawa"
      email               = "???"
      rdn_serial_number   = "1231583-1"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "33:21:e3:69:53:43:67:79:59:80:30:b7"
      )
}
