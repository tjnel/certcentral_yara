import "pe"

rule MAL_Compromised_Cert_WagmiTraffer_GlobalSign_3A48F81C499161FD0C9C072A {
   meta:
      description         = "Detects WagmiTraffer with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-26"
      version             = "1.0"

      hash                = "721102a038d4bcb4828d2bea12e6b31d2818c4c8f8cff36c1fd0ad88ab29d616"
      malware             = "WagmiTraffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LISTERA LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "3a:48:f8:1c:49:91:61:fd:0c:9c:07:2a"
      cert_thumbprint     = "7D7C67575E2B7684887BB60BE3F138B6522080F4"
      cert_valid_from     = "2025-05-26"
      cert_valid_to       = "2026-05-16"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "3a:48:f8:1c:49:91:61:fd:0c:9c:07:2a"
      )
}
