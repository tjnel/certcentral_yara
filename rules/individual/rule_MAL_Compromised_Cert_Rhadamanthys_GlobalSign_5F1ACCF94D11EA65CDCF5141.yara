import "pe"

rule MAL_Compromised_Cert_Rhadamanthys_GlobalSign_5F1ACCF94D11EA65CDCF5141 {
   meta:
      description         = "Detects Rhadamanthys with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-08"
      version             = "1.0"

      hash                = "8bdd5af6605a576e7a2e561cb2624b30b7c0afb349a76a8cc80bdb6f994fa773"
      malware             = "Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "Shantou Matching Trade Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "5f:1a:cc:f9:4d:11:ea:65:cd:cf:51:41"
      cert_thumbprint     = "C5E19C953193B15F6C7CC1BB72D8DBD261FC5BB8"
      cert_valid_from     = "2024-05-08"
      cert_valid_to       = "2025-05-09"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Shantou"
      email               = "???"
      rdn_serial_number   = "91440500MA4WEUU96H"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "5f:1a:cc:f9:4d:11:ea:65:cd:cf:51:41"
      )
}
