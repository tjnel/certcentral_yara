import "pe"

rule MAL_Compromised_Cert_MacSync_Stealer_Apple_29A552D8DFF80468 {
   meta:
      description         = "Detects MacSync Stealer with compromised cert (Apple)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-14"
      version             = "1.0"

      hash                = "4ae745bc0e4631f676b3d0a05d5c74e37bdfc8da3076208b24e73e5bbea9178f"
      malware             = "MacSync Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "OKAN ATAKOL"
      cert_issuer_short   = "Apple"
      cert_issuer         = "Apple Inc."
      cert_serial         = "29:a5:52:d8:df:f8:04:68"
      cert_thumbprint     = "2DBDA81B0F97D886D93223D5B1ED438885F3CDF3"
      cert_valid_from     = "2025-11-14"
      cert_valid_to       = "2027-02-01"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Apple Inc." and
         sig.serial == "29:a5:52:d8:df:f8:04:68"
      )
}
