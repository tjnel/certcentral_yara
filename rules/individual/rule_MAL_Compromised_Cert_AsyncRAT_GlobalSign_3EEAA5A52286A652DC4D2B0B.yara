import "pe"

rule MAL_Compromised_Cert_AsyncRAT_GlobalSign_3EEAA5A52286A652DC4D2B0B {
   meta:
      description         = "Detects AsyncRAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-01"
      version             = "1.0"

      hash                = "9f65fc1f458f2c33ac5547561a6ada98688817e3c362e9d38e2b2b6ce79df4bf"
      malware             = "AsyncRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "成都云祺科技有限公司"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "3e:ea:a5:a5:22:86:a6:52:dc:4d:2b:0b"
      cert_thumbprint     = "3A10BC1907E7B5ED1D180F183B8774B414D35E69"
      cert_valid_from     = "2025-07-01"
      cert_valid_to       = "2028-07-01"

      country             = "CN"
      state               = "四川省"
      locality            = "成都市"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "3e:ea:a5:a5:22:86:a6:52:dc:4d:2b:0b"
      )
}
