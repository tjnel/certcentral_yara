import "pe"

rule MAL_Compromised_Cert_FakeWallet_GlobalSign_4345DF897AA6792193B2F67A {
   meta:
      description         = "Detects FakeWallet with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-27"
      version             = "1.0"

      hash                = "f0a637405491bfa9f50cd5bcb568ec7c6e0b03244a634cad80ad5b0c150f3128"
      malware             = "FakeWallet"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Shijiazhuang Jinghang Laser Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "43:45:df:89:7a:a6:79:21:93:b2:f6:7a"
      cert_thumbprint     = "6BFBD2ED9D6C207CEE8E488B7916968F69030748"
      cert_valid_from     = "2025-03-27"
      cert_valid_to       = "2026-03-28"

      country             = "CN"
      state               = "Hebei"
      locality            = "Shijiazhuang"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "43:45:df:89:7a:a6:79:21:93:b2:f6:7a"
      )
}
