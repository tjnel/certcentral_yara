import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_7C19DEA4E1DE1363A3B20192 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-08"
      version             = "1.0"

      hash                = "13e8b56bdd486f138923f66e3c6319d3d296968febfebd8224a656b559960f9e"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Guangzhou Anfeide Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "7c:19:de:a4:e1:de:13:63:a3:b2:01:92"
      cert_thumbprint     = "88b9aa3ef89279b1b2f5fd615618ff6430862fd5f1245c04a7884e19699b4eb8"
      cert_valid_from     = "2024-11-08"
      cert_valid_to       = "2025-11-09"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Guangzhou"
      email               = "???"
      rdn_serial_number   = "91440101MA59RW850A"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "7c:19:de:a4:e1:de:13:63:a3:b2:01:92"
      )
}
