import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_5746A0AA56B4D3E03289D656 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-09"
      version             = "1.0"

      hash                = "9c8db1a4035cd61f3586dbad1e008e911256606b27be53f2eaa34c1fcfcc8129"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "FACTICA SOFTWARE INC."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "57:46:a0:aa:56:b4:d3:e0:32:89:d6:56"
      cert_thumbprint     = "16C665BBDA00A19D46B1E10F6CF1586C2ACF9778"
      cert_valid_from     = "2024-10-09"
      cert_valid_to       = "2025-10-10"

      country             = "CA"
      state               = "Ontario"
      locality            = "Ottawa"
      email               = "???"
      rdn_serial_number   = "964799-6"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "57:46:a0:aa:56:b4:d3:e0:32:89:d6:56"
      )
}
