import "pe"

rule MAL_Compromised_Cert_Rhadamanthys_GlobalSign_424DAE86E4D976F2EC31FA76 {
   meta:
      description         = "Detects Rhadamanthys with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-17"
      version             = "1.0"

      hash                = "9de12a0eecc54548338319c106bb77ca5496c1aedc293d22dc994eb61b9dd984"
      malware             = "Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "Reviihuray Communication Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "42:4d:ae:86:e4:d9:76:f2:ec:31:fa:76"
      cert_thumbprint     = "CA76DA81C13B8722F4D076E6D1FD39574F22AD66"
      cert_valid_from     = "2024-05-17"
      cert_valid_to       = "2025-05-16"

      country             = "CN"
      state               = "Hebei"
      locality            = "Shijiazhuang"
      email               = "???"
      rdn_serial_number   = "91130108MA09RXE44W"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "42:4d:ae:86:e4:d9:76:f2:ec:31:fa:76"
      )
}
