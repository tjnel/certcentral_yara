import "pe"

rule MAL_Compromised_Cert_HijackLoader_GlobalSign_5B5D9C65E0953B3F15D0D5DE {
   meta:
      description         = "Detects HijackLoader with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-12-21"
      version             = "1.0"

      hash                = "fa63d50848b4f806abafe637f931f20bcf625366051ec148e3f5e030dd30d1fa"
      malware             = "HijackLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "RiskGuard WinArk Software Tech Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "5b:5d:9c:65:e0:95:3b:3f:15:d0:d5:de"
      cert_thumbprint     = "6903647A479A0D8B48F6BC0D73320896B0377736"
      cert_valid_from     = "2023-12-21"
      cert_valid_to       = "2024-12-21"

      country             = "CN"
      state               = "Liaoning"
      locality            = "Dalian"
      email               = "???"
      rdn_serial_number   = "91210242MA0YGH36XJ"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "5b:5d:9c:65:e0:95:3b:3f:15:d0:d5:de"
      )
}
