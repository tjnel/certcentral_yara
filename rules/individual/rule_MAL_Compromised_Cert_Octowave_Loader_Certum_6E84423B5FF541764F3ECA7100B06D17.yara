import "pe"

rule MAL_Compromised_Cert_Octowave_Loader_Certum_6E84423B5FF541764F3ECA7100B06D17 {
   meta:
      description         = "Detects Octowave Loader with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-02"
      version             = "1.0"

      hash                = "9ad4274d21feed404714b504eb3a076745e0250a9e62dfdb2615b5614eb9287e"
      malware             = "Octowave Loader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LeYao Network Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "6e:84:42:3b:5f:f5:41:76:4f:3e:ca:71:00:b0:6d:17"
      cert_thumbprint     = "C5D93C655202104525F207C9B101B00C330481B7"
      cert_valid_from     = "2024-12-02"
      cert_valid_to       = "2025-12-02"

      country             = "CN"
      state               = "Hebei"
      locality            = "Qinhuangdao"
      email               = "???"
      rdn_serial_number   = "91130302MA0G33CQ5Q"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "6e:84:42:3b:5f:f5:41:76:4f:3e:ca:71:00:b0:6d:17"
      )
}
