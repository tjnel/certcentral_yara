import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_0FD011B4BCCCC4F86E60FAB1 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-07"
      version             = "1.0"

      hash                = "585ab6c1cdaa65c9d08decf4e1ab1cf9327f00e18d13e85e338268ccc3587aab"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "WINSTA SPORTS PRIVATE LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "0f:d0:11:b4:bc:cc:c4:f8:6e:60:fa:b1"
      cert_thumbprint     = "CD7B93AF5A590CE793D945B40EB33F42DCB3927E"
      cert_valid_from     = "2025-03-07"
      cert_valid_to       = "2026-03-08"

      country             = "IN"
      state               = "Rajasthan"
      locality            = "Jaipur"
      email               = "bunnyisbk47@gmail.com"
      rdn_serial_number   = "U92419RJ2021PTC078915"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "0f:d0:11:b4:bc:cc:c4:f8:6e:60:fa:b1"
      )
}
