import "pe"

rule MAL_Compromised_Cert_UNK_50_GlobalSign_4169E1D8BB961B8815ADA210 {
   meta:
      description         = "Detects UNK-50 with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-07"
      version             = "1.0"

      hash                = "7e05b76b877e2cf8d191877c490daee1030c75d8fc1bb1428f78e8880890e046"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "COMPAÑIA DE DESARROLLO DE VEHICULOS Y BICICLETAS ELECTRICAS SL"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "41:69:e1:d8:bb:96:1b:88:15:ad:a2:10"
      cert_thumbprint     = "E677C66C44403DFB15FB3415C6EBC9E2F9A8BA37"
      cert_valid_from     = "2025-08-07"
      cert_valid_to       = "2026-08-08"

      country             = "ES"
      state               = "Málaga"
      locality            = "Málaga"
      email               = "???"
      rdn_serial_number   = "B93271294"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "41:69:e1:d8:bb:96:1b:88:15:ad:a2:10"
      )
}
