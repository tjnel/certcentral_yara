import "pe"

rule MAL_Compromised_Cert_gh0stRAT_GlobalSign_40E90E0B6789811000910DBD {
   meta:
      description         = "Detects gh0stRAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-11"
      version             = "1.0"

      hash                = "9e78f89ffa70b6426595e1007db89bc2bd9fd39600d659a347f4689c5a1e67ad"
      malware             = "gh0stRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "CubTiger Network Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "40:e9:0e:0b:67:89:81:10:00:91:0d:bd"
      cert_thumbprint     = "C6F65585AA0FFFFCF16DB62E8E6AA49B87F2A0A3"
      cert_valid_from     = "2024-10-11"
      cert_valid_to       = "2025-10-12"

      country             = "CN"
      state               = "Beijing"
      locality            = "Beijing"
      email               = "???"
      rdn_serial_number   = "91110229MA01R14F61"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "40:e9:0e:0b:67:89:81:10:00:91:0d:bd"
      )
}
