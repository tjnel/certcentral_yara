import "pe"

rule MAL_Compromised_Cert_SnipBot_GlobalSign_3B0E3879266F3BC98225B390 {
   meta:
      description         = "Detects SnipBot with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-04-02"
      version             = "1.0"

      hash                = "5c71601717bed14da74980ad554ad35d751691b2510653223c699e1f006195b8"
      malware             = "SnipBot"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Hangzhou Yueju Apparel Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "3b:0e:38:79:26:6f:3b:c9:82:25:b3:90"
      cert_thumbprint     = "2EAB64A4EAF37060D27620A822DF2E1F18AC28F6"
      cert_valid_from     = "2024-04-02"
      cert_valid_to       = "2025-04-03"

      country             = "CN"
      state               = "Zhejiang"
      locality            = "Hangzhou"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "3b:0e:38:79:26:6f:3b:c9:82:25:b3:90"
      )
}
