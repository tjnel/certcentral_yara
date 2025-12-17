import "pe"

rule MAL_Compromised_Cert_TrojanizedTrading_GlobalSign_6968631F56D94F189DA04A7A {
   meta:
      description         = "Detects TrojanizedTrading with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-12"
      version             = "1.0"

      hash                = "168002d1fd7f71fce5a08fb1b1fdeac1a8afec8a5f3465245ba87ccc9b2b6a37"
      malware             = "TrojanizedTrading"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Chengdu Pengliang Trading Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "69:68:63:1f:56:d9:4f:18:9d:a0:4a:7a"
      cert_thumbprint     = "0286243AF1F58A6ECDEC75EE9D380681556B06DD"
      cert_valid_from     = "2025-06-12"
      cert_valid_to       = "2026-06-13"

      country             = "CN"
      state               = "Sichuan"
      locality            = "Chengdu"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "69:68:63:1f:56:d9:4f:18:9d:a0:4a:7a"
      )
}
