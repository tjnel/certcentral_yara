import "pe"

rule MAL_Compromised_Cert_DeerStealer_GlobalSign_505F39515DA558182324C2CA {
   meta:
      description         = "Detects DeerStealer with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-16"
      version             = "1.0"

      hash                = "cfb5cb22b2b882d620507a88942a4bfe66fd65082b918b1b9a6699fd56ac5a9d"
      malware             = "DeerStealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xingtai Yali Intelligent Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "50:5f:39:51:5d:a5:58:18:23:24:c2:ca"
      cert_thumbprint     = "F3C09C8B7985B3FC4A4B4AA5789C9BD161BD5EFB"
      cert_valid_from     = "2024-12-16"
      cert_valid_to       = "2025-12-17"

      country             = "CN"
      state               = "Hebei"
      locality            = "Xingtai"
      email               = "???"
      rdn_serial_number   = "91130503MA0G685G99"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "50:5f:39:51:5d:a5:58:18:23:24:c2:ca"
      )
}
