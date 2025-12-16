import "pe"

rule MAL_Compromised_Cert_Latrodectus_GlobalSign_1842364451D5932004E163C7 {
   meta:
      description         = "Detects Latrodectus with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-31"
      version             = "1.0"

      hash                = "ec3ca0877e599ae9c40cbcec51a9a4718114e33d9e2d9d8c72f5f24d7cebdcbf"
      malware             = "Latrodectus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC CESARIA"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "18:42:36:44:51:d5:93:20:04:e1:63:c7"
      cert_thumbprint     = "239E18C2FF083DAB3546B83BE3CC00756442047D"
      cert_valid_from     = "2024-05-31"
      cert_valid_to       = "2025-06-01"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1247700263821"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "18:42:36:44:51:d5:93:20:04:e1:63:c7"
      )
}
