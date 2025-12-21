import "pe"

rule MAL_Compromised_Cert_CrazyEvil_Traffer_GlobalSign_61B6B482F4D2937533E8A07B {
   meta:
      description         = "Detects CrazyEvil Traffer with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-03"
      version             = "1.0"

      hash                = "f427cc8ba338c1400a9576f6ae8008ab16ca358e391c2cbca459cf6def30b354"
      malware             = "CrazyEvil Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SZVERES MARKETING SRL"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "61:b6:b4:82:f4:d2:93:75:33:e8:a0:7b"
      cert_thumbprint     = ""
      cert_valid_from     = "2025-10-03"
      cert_valid_to       = "2026-10-04"

      country             = "RO"
      state               = "Timiș"
      locality            = "Biled"
      email               = ""
      rdn_serial_number   = "J35/1100/2022"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "61:b6:b4:82:f4:d2:93:75:33:e8:a0:7b"
      )
}
