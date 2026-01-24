import "pe"

rule MAL_Compromised_Cert_Traffer_Certum_02C051F69D1FF9A0B7D8614772634B90 {
   meta:
      description         = "Detects Traffer with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-21"
      version             = "1.0"

      hash                = "bf93c8ec25cc6d40a2803bf3f72aa8c59d52f56db03f9ab37d187bdbc7bd82c3"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Shanghai Xizetai Network Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "02:c0:51:f6:9d:1f:f9:a0:b7:d8:61:47:72:63:4b:90"
      cert_thumbprint     = "268ACBF84CA0E15459BD4ED4274E6974D7A1714F"
      cert_valid_from     = "2025-11-21"
      cert_valid_to       = "2026-11-21"

      country             = "CN"
      state               = "Shanghai"
      locality            = "Shanghai"
      email               = "???"
      rdn_serial_number   = "91310000MABXBL2X7J"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "02:c0:51:f6:9d:1f:f9:a0:b7:d8:61:47:72:63:4b:90"
      )
}
