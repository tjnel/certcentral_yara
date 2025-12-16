import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_1FDB22030768A9CF31F2A96A {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-25"
      version             = "1.0"

      hash                = "37bf1269a21cba22af239e734de043f1d08d61b44414bcf63b1b9198e6a8bc87"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "HOA SEN HA NAM ONE MEMBER LIMITED LIABILITIES COMPANY"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "1f:db:22:03:07:68:a9:cf:31:f2:a9:6a"
      cert_thumbprint     = "A0CA753F0845B420E3F25E200B81D9936E731875"
      cert_valid_from     = "2024-11-25"
      cert_valid_to       = "2025-11-26"

      country             = "VN"
      state               = "Ha Nam"
      locality            = "Ha Nam"
      email               = "???"
      rdn_serial_number   = "0700759219"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "1f:db:22:03:07:68:a9:cf:31:f2:a9:6a"
      )
}
