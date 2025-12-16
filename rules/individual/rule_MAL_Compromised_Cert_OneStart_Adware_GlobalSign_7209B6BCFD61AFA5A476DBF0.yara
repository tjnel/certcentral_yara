import "pe"

rule MAL_Compromised_Cert_OneStart_Adware_GlobalSign_7209B6BCFD61AFA5A476DBF0 {
   meta:
      description         = "Detects OneStart Adware with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-10"
      version             = "1.0"

      hash                = "7ae44a0606e74fa34cde274a0ed05b899992a9cda60124e8c60403774c7206bc"
      malware             = "OneStart Adware"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Apollo Technologies Inc."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "72:09:b6:bc:fd:61:af:a5:a4:76:db:f0"
      cert_thumbprint     = "B515DF656EE4C27ED1F9FEBC2CE6F9756E6F023B"
      cert_valid_from     = "2024-05-10"
      cert_valid_to       = "2027-05-11"

      country             = "PA"
      state               = "Panama"
      locality            = "Panama City"
      email               = "???"
      rdn_serial_number   = "155722923"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "72:09:b6:bc:fd:61:af:a5:a4:76:db:f0"
      )
}
