import "pe"

rule MAL_Compromised_Cert_ValleyRAT_GlobalSign_05B4BC293E3AC7D14DAEBF6E {
   meta:
      description         = "Detects ValleyRAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-18"
      version             = "1.0"

      hash                = "2b2363d3759ef8b676f398fc413c56a1058b8bc9c5633f24c55538e5ba501afb"
      malware             = "ValleyRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Nanjing Yueyue Kunkun Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "05:b4:bc:29:3e:3a:c7:d1:4d:ae:bf:6e"
      cert_thumbprint     = "9D2B08A9463C6B9040544DC6547E52C85D9DD645"
      cert_valid_from     = "2025-07-18"
      cert_valid_to       = "2026-07-19"

      country             = "CN"
      state               = "Jiangsu"
      locality            = "Nanjing"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "05:b4:bc:29:3e:3a:c7:d1:4d:ae:bf:6e"
      )
}
