import "pe"

rule MAL_Compromised_Cert_RUS_51_GlobalSign_4F2343D96154B941DB0A26B2 {
   meta:
      description         = "Detects RUS-51 with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-12-29"
      version             = "1.0"

      hash                = "ff82c4c679c5486aed2d66a802682245a1e9cd7d6ceb65fa0e7b222f902998e8"
      malware             = "RUS-51"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "KouisMoa MegaByte Information Technolog Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "4f:23:43:d9:61:54:b9:41:db:0a:26:b2"
      cert_thumbprint     = "32A9B43EB22374AE870D5AC1C5357889CDF1C9E8"
      cert_valid_from     = "2023-12-29"
      cert_valid_to       = "2024-12-29"

      country             = "CN"
      state               = "Hubei"
      locality            = "Xiangyang"
      email               = "???"
      rdn_serial_number   = "91420600MA488H2M4C"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "4f:23:43:d9:61:54:b9:41:db:0a:26:b2"
      )
}
