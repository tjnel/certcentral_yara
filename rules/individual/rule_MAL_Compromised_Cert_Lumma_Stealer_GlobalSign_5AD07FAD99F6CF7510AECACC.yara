import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_GlobalSign_5AD07FAD99F6CF7510AECACC {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-08-11"
      version             = "1.0"

      hash                = "1e37fad328fe34aa991f28ab5654e2732b0886e65ccb45a4dcd81a36bddbb2a8"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "Chengdu Legou Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "5a:d0:7f:ad:99:f6:cf:75:10:ae:ca:cc"
      cert_thumbprint     = "F9BF3B25C198F70DCF459F6608E1F01630AB359A"
      cert_valid_from     = "2023-08-11"
      cert_valid_to       = "2025-10-21"

      country             = "CN"
      state               = "Sichuan"
      locality            = "Chengdu"
      email               = "???"
      rdn_serial_number   = "91510100MA62PN8777"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "5a:d0:7f:ad:99:f6:cf:75:10:ae:ca:cc"
      )
}
