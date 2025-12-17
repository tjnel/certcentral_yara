import "pe"

rule MAL_Compromised_Cert_BumbleBee_GlobalSign_669F5C8918D3B19E81282765 {
   meta:
      description         = "Detects BumbleBee with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-27"
      version             = "1.0"

      hash                = "281e07af77e1ff21140a7102c3cf8802dff96e670c8c3c73b8250d487a5196ed"
      malware             = "BumbleBee"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "CanDllerWhale Electronic Studios Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "66:9f:5c:89:18:d3:b1:9e:81:28:27:65"
      cert_thumbprint     = "85D0BB733BF014A4A15550622D5EB7815BC2DB39"
      cert_valid_from     = "2025-03-27"
      cert_valid_to       = "2026-03-28"

      country             = "CN"
      state               = "Sichuan"
      locality            = "Chengdu"
      email               = "???"
      rdn_serial_number   = "91510107MA6AFMP91G"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "66:9f:5c:89:18:d3:b1:9e:81:28:27:65"
      )
}
