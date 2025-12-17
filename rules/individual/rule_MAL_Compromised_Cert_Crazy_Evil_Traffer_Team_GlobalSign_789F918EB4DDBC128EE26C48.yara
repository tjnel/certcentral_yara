import "pe"

rule MAL_Compromised_Cert_Crazy_Evil_Traffer_Team_GlobalSign_789F918EB4DDBC128EE26C48 {
   meta:
      description         = "Detects Crazy Evil Traffer Team with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-14"
      version             = "1.0"

      hash                = "05c016653471647aabc0be3d36fe94862290afc0f41a348db031763a5d8d6f46"
      malware             = "Crazy Evil Traffer Team"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "Meizhou Fisherman Network Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "78:9f:91:8e:b4:dd:bc:12:8e:e2:6c:48"
      cert_thumbprint     = "1CDF48EA9702F84214346FD42BF4392D02199006"
      cert_valid_from     = "2025-05-14"
      cert_valid_to       = "2026-05-15"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Meizhou"
      email               = "???"
      rdn_serial_number   = "91441403MA4UNLKT9A"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "78:9f:91:8e:b4:dd:bc:12:8e:e2:6c:48"
      )
}
