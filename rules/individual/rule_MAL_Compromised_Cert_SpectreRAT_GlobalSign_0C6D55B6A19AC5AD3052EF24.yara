import "pe"

rule MAL_Compromised_Cert_SpectreRAT_GlobalSign_0C6D55B6A19AC5AD3052EF24 {
   meta:
      description         = "Detects SpectreRAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-01-31"
      version             = "1.0"

      hash                = "94827a4ab543972eacee8e610ec94d8469de43fe8dc0302015f1c587b158025d"
      malware             = "SpectreRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "JauiInderte Agiletron Information Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "0c:6d:55:b6:a1:9a:c5:ad:30:52:ef:24"
      cert_thumbprint     = "D0C7D82E733D076804E5DFF6FB93069D2F9CB192"
      cert_valid_from     = "2024-01-31"
      cert_valid_to       = "2025-01-31"

      country             = "CN"
      state               = "Anhui"
      locality            = "Wuhu"
      email               = "???"
      rdn_serial_number   = "91340222MA2MXM3F23"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "0c:6d:55:b6:a1:9a:c5:ad:30:52:ef:24"
      )
}
