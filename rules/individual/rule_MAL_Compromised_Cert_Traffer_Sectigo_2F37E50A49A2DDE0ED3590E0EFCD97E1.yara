import "pe"

rule MAL_Compromised_Cert_Traffer_Sectigo_2F37E50A49A2DDE0ED3590E0EFCD97E1 {
   meta:
      description         = "Detects Traffer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-03"
      version             = "1.0"

      hash                = "39db9d449c0222f0b2f2ca058bf901de6ddfb09ac7663540c84df92860bb5ad4"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = "Malicious fake meeting installers  targeting crypto users worldwide"

      signer              = "Canton Pure Jonna Network Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "2f:37:e5:0a:49:a2:dd:e0:ed:35:90:e0:ef:cd:97:e1"
      cert_thumbprint     = "7DBD12B7913FB91CBF9E5C1FD894BF09513714A3"
      cert_valid_from     = "2025-10-03"
      cert_valid_to       = "2026-10-03"

      country             = "CN"
      state               = "Guangdong Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91440114MACL0TN54Q"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "2f:37:e5:0a:49:a2:dd:e0:ed:35:90:e0:ef:cd:97:e1"
      )
}
