import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_115D73560CE2DD101D5BD925 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-25"
      version             = "1.0"

      hash                = "d2f5a074c5ea4c29523cca520f52f9dae3e3ab0c900be97367613f703e4daec8"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "TAU CENTAURI LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "11:5d:73:56:0c:e2:dd:10:1d:5b:d9:25"
      cert_thumbprint     = "F38B5E3A3A9807A36BC947B75BF14BC8091C83A7"
      cert_valid_from     = "2025-02-25"
      cert_valid_to       = "2026-02-26"

      country             = "IL"
      state               = "Central District"
      locality            = "Ra'anana"
      email               = "contactus@taucentauriltd.com"
      rdn_serial_number   = "516234788"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "11:5d:73:56:0c:e2:dd:10:1d:5b:d9:25"
      )
}
