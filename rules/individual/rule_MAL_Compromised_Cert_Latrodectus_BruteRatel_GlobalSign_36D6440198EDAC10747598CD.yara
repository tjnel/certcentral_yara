import "pe"

rule MAL_Compromised_Cert_Latrodectus_BruteRatel_GlobalSign_36D6440198EDAC10747598CD {
   meta:
      description         = "Detects Latrodectus,BruteRatel with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-06"
      version             = "1.0"

      hash                = "83859acdf4ac22927fa88f715666653807501db6f1865a3657599b4c5d130bb2"
      malware             = "Latrodectus,BruteRatel"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC LOFT"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "36:d6:44:01:98:ed:ac:10:74:75:98:cd"
      cert_thumbprint     = "02346AF23A5ED2E4C67A8D4E5EF4094E9540C4FF"
      cert_valid_from     = "2024-06-06"
      cert_valid_to       = "2025-06-07"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1247700070595"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "36:d6:44:01:98:ed:ac:10:74:75:98:cd"
      )
}
