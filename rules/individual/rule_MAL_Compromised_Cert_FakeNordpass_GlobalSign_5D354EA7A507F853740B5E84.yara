import "pe"

rule MAL_Compromised_Cert_FakeNordpass_GlobalSign_5D354EA7A507F853740B5E84 {
   meta:
      description         = "Detects FakeNordpass with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-13"
      version             = "1.0"

      hash                = "88b77a6ddc88be7a2ccfc6a518c06457656c3fdb60c9445c32aba4d24211a969"
      malware             = "FakeNordpass"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Shijiazhuang SUNRISE Carpet Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "5d:35:4e:a7:a5:07:f8:53:74:0b:5e:84"
      cert_thumbprint     = "478CF418040D3AC581ED12EDA481AB39792CA73C"
      cert_valid_from     = "2025-03-13"
      cert_valid_to       = "2026-03-14"

      country             = "CN"
      state               = "Hebei"
      locality            = "Shijiazhuang"
      email               = "???"
      rdn_serial_number   = "91130105774415592W"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "5d:35:4e:a7:a5:07:f8:53:74:0b:5e:84"
      )
}
