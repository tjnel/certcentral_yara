import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_3092CC6FE5721C75BA8613A7 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-21"
      version             = "1.0"

      hash                = "b453d7fcc518d8ade1d492c61c4d09a36672848c92083c39dfb233e412f5df55"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC Territory of Comfort"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "30:92:cc:6f:e5:72:1c:75:ba:86:13:a7"
      cert_thumbprint     = "0B0A87DCBF5FC6EDAE90D3B4A8B0EDADE6C4DC1D"
      cert_valid_from     = "2025-04-21"
      cert_valid_to       = "2026-04-22"

      country             = "RU"
      state               = "Tambov Oblast"
      locality            = "Tambov"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "30:92:cc:6f:e5:72:1c:75:ba:86:13:a7"
      )
}
