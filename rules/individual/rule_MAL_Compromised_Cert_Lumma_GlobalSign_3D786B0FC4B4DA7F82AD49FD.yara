import "pe"

rule MAL_Compromised_Cert_Lumma_GlobalSign_3D786B0FC4B4DA7F82AD49FD {
   meta:
      description         = "Detects Lumma with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-06"
      version             = "1.0"

      hash                = "c6a9478bc78e96f2eb72543c98d00ec3c06ee00cffe98423f93e0a7016d468e2"
      malware             = "Lumma"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "THIRTY THREE (SHANGHAI)LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "3d:78:6b:0f:c4:b4:da:7f:82:ad:49:fd"
      cert_thumbprint     = ""
      cert_valid_from     = "2025-05-06"
      cert_valid_to       = "2026-05-07"

      country             = "CN"
      state               = "Shanghai"
      locality            = "Shanghai"
      email               = ""
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "3d:78:6b:0f:c4:b4:da:7f:82:ad:49:fd"
      )
}
