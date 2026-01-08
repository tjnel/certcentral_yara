import "pe"

rule MAL_Compromised_Cert_ValleyRAT_Certum_51EC6208C20191DB2EC825969E857A68 {
   meta:
      description         = "Detects ValleyRAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-30"
      version             = "1.0"

      hash                = "ed868c0bbf654880d014f954e935039c5d3a4ad7d615912277c4502bf67964cf"
      malware             = "ValleyRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "Identified as ValleyRAT by multiple sandboxes: https://tria.ge/260106-1yj3hacp2t/behavioral2"

      signer              = "福州大顿商贸有限公司"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "51:ec:62:08:c2:01:91:db:2e:c8:25:96:9e:85:7a:68"
      cert_thumbprint     = "C7C00EF798E9E36E00DF34711FFB2A48F1B89686"
      cert_valid_from     = "2025-12-30"
      cert_valid_to       = "2026-12-30"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "51:ec:62:08:c2:01:91:db:2e:c8:25:96:9e:85:7a:68"
      )
}
