import "pe"

rule MAL_Compromised_Cert_Rhadamanthys_GlobalSign_53EFF7D7C3CB4266E8B75E6B {
   meta:
      description         = "Detects Rhadamanthys with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-03"
      version             = "1.0"

      hash                = "b1fa0c62e07f9ad0a625fd1474a197c1d687b985714c3d697981f5fbe4993266"
      malware             = "Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "Hebei Kangsheng Agricultural Science & Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "53:ef:f7:d7:c3:cb:42:66:e8:b7:5e:6b"
      cert_thumbprint     = "39CA684447AADD97E2C237D5543BB198E00CB6C8"
      cert_valid_from     = "2025-01-03"
      cert_valid_to       = "2026-01-04"

      country             = "CN"
      state               = "Hebei"
      locality            = "Hengshui"
      email               = "???"
      rdn_serial_number   = "91131101059447675D"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "53:ef:f7:d7:c3:cb:42:66:e8:b7:5e:6b"
      )
}
