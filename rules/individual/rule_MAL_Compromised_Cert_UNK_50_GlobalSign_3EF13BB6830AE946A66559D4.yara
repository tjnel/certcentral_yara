import "pe"

rule MAL_Compromised_Cert_UNK_50_GlobalSign_3EF13BB6830AE946A66559D4 {
   meta:
      description         = "Detects UNK-50 with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-04"
      version             = "1.0"

      hash                = "db5cc6b8d0384176adc1349733e516cd17bbd4d29de8cb96f7ccfa5cd6a5199f"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "PURPLE SALES LLP"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "3e:f1:3b:b6:83:0a:e9:46:a6:65:59:d4"
      cert_thumbprint     = "83754BA05B499A26C2699DB7250ADABCE0269DFD"
      cert_valid_from     = "2025-08-04"
      cert_valid_to       = "2026-08-05"

      country             = "IN"
      state               = "West Bengal"
      locality            = "Kolkata"
      email               = "purplegroupindia@gmail.com"
      rdn_serial_number   = "AAN-1168"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "3e:f1:3b:b6:83:0a:e9:46:a6:65:59:d4"
      )
}
