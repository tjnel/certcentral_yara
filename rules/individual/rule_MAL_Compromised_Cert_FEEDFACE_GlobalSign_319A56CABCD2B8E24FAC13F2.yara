import "pe"

rule MAL_Compromised_Cert_FEEDFACE_GlobalSign_319A56CABCD2B8E24FAC13F2 {
   meta:
      description         = "Detects FEEDFACE with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-11"
      version             = "1.0"

      hash                = "166aa6eb2da5e895d133391a36281a3d8b917b4a96265f7f8f9da3d76ca1f528"
      malware             = "FEEDFACE"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "湘西经开区麟尤电子商务有限公司"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "31:9a:56:ca:bc:d2:b8:e2:4f:ac:13:f2"
      cert_thumbprint     = "8D0D36292E244447A6CA5C08AFE8D5D5766A69CB"
      cert_valid_from     = "2024-06-11"
      cert_valid_to       = "2025-06-12"

      country             = "CN"
      state               = "Hunan"
      locality            = "Xiangxi"
      email               = "???"
      rdn_serial_number   = "91433101MADJXRK258"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "31:9a:56:ca:bc:d2:b8:e2:4f:ac:13:f2"
      )
}
