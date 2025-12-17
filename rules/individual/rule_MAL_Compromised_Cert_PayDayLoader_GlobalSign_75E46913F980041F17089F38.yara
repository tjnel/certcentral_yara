import "pe"

rule MAL_Compromised_Cert_PayDayLoader_GlobalSign_75E46913F980041F17089F38 {
   meta:
      description         = "Detects PayDayLoader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-15"
      version             = "1.0"

      hash                = "86653cee7b63f7ced22546693b7f86c65c439dce97612be9cdf9aeccdd59c1df"
      malware             = "PayDayLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ICEL LOGISTICS COMPANY LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "75:e4:69:13:f9:80:04:1f:17:08:9f:38"
      cert_thumbprint     = "31F9D9A6B70A5B9AA73025F45ACA1E562C35CC87"
      cert_valid_from     = "2024-10-15"
      cert_valid_to       = "2025-10-16"

      country             = "VN"
      state               = "Ha Noi"
      locality            = "Ha Noi"
      email               = "elmabordonbwa63@gmail.com"
      rdn_serial_number   = "0108307780"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "75:e4:69:13:f9:80:04:1f:17:08:9f:38"
      )
}
