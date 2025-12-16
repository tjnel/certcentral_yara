import "pe"

rule MAL_Compromised_Cert_RemcosRAT_GlobalSign_7CC47A19B9258F9A884585C5 {
   meta:
      description         = "Detects RemcosRAT with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-06"
      version             = "1.0"

      hash                = "6493d8528b5aca043772c1f657125bcebc0cf762efc69b7e3c99b2f4a3095726"
      malware             = "RemcosRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC CiTyAr GROUP"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "7c:c4:7a:19:b9:25:8f:9a:88:45:85:c5"
      cert_thumbprint     = "A2F30B8E19DDF63A86DA92FD40B08898B485756A"
      cert_valid_from     = "2025-05-06"
      cert_valid_to       = "2026-05-07"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1137746413507"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "7c:c4:7a:19:b9:25:8f:9a:88:45:85:c5"
      )
}
