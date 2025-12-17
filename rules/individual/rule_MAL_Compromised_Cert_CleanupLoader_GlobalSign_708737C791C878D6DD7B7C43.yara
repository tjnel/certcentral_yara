import "pe"

rule MAL_Compromised_Cert_CleanupLoader_GlobalSign_708737C791C878D6DD7B7C43 {
   meta:
      description         = "Detects CleanupLoader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-13"
      version             = "1.0"

      hash                = "92d2488e401d24a4bfc1598d813bc53af5c225769efedf0c7e5e4083623f4486"
      malware             = "CleanupLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Langfang Alkem Material Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "70:87:37:c7:91:c8:78:d6:dd:7b:7c:43"
      cert_thumbprint     = "7ED7081EE612FBF9FE0ADE46F4A2749DA20251E0"
      cert_valid_from     = "2024-09-13"
      cert_valid_to       = "2025-09-14"

      country             = "CN"
      state               = "Hebei"
      locality            = "Langfang"
      email               = "???"
      rdn_serial_number   = "9113102459540314XR"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "70:87:37:c7:91:c8:78:d6:dd:7b:7c:43"
      )
}
