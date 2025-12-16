import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_4752DC1DBCB8091355C59B37 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-11"
      version             = "1.0"

      hash                = "435f44f8a3d5cc03d6a95d5295dc8a7ecf44ade26add5c9ac1f47f8a609a36dd"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "TRUONG LUU THUY PHARMA COMPANY LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "47:52:dc:1d:bc:b8:09:13:55:c5:9b:37"
      cert_thumbprint     = "889C0380C94768A7894E1C21FF8B10D26D8E07FD"
      cert_valid_from     = "2024-12-11"
      cert_valid_to       = "2025-12-12"

      country             = "VN"
      state               = "Ha Nam"
      locality            = "Ha Nam"
      email               = "kewfanghuava398@gmail.com"
      rdn_serial_number   = "0700861879"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "47:52:dc:1d:bc:b8:09:13:55:c5:9b:37"
      )
}
