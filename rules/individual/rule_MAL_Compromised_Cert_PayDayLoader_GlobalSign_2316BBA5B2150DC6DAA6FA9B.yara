import "pe"

rule MAL_Compromised_Cert_PayDayLoader_GlobalSign_2316BBA5B2150DC6DAA6FA9B {
   meta:
      description         = "Detects PayDayLoader with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-13"
      version             = "1.0"

      hash                = "9963af60316bb5da48072145ba147b82588f7ac56448d3723dd6629118bbed35"
      malware             = "PayDayLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "K.MY TRADING TRANSPORT COMPANY LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "23:16:bb:a5:b2:15:0d:c6:da:a6:fa:9b"
      cert_thumbprint     = "E3AC11D2E804AA9464780ACA008193AEB430B48E"
      cert_valid_from     = "2024-12-13"
      cert_valid_to       = "2025-12-14"

      country             = "VN"
      state               = "Ha Nam"
      locality            = "Ha Nam"
      email               = "omeyakalima1@gmail.com"
      rdn_serial_number   = "0700867207"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "23:16:bb:a5:b2:15:0d:c6:da:a6:fa:9b"
      )
}
