import "pe"

rule MAL_Compromised_Cert_AsyncRAT_Sectigo_00D5AC27BD4F6FDF41BD91C2162EB343E1 {
   meta:
      description         = "Detects AsyncRAT with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-25"
      version             = "1.0"

      hash                = "5834d20cfc80f6fe20514b7a1e3e9764765aa3f548e2874504e9d26345f80560"
      malware             = "AsyncRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Wenzhou Feixun Internet Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:d5:ac:27:bd:4f:6f:df:41:bd:91:c2:16:2e:b3:43:e1"
      cert_thumbprint     = "47E55F48CA38C8C47CD1548B72C231E64F9B0CD5"
      cert_valid_from     = "2025-11-25"
      cert_valid_to       = "2026-11-25"

      country             = "CN"
      state               = "Zhejiang Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91330302MA2H91PU2D"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:d5:ac:27:bd:4f:6f:df:41:bd:91:c2:16:2e:b3:43:e1"
      )
}
