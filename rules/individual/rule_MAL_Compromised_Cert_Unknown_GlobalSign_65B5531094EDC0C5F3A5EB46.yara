import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_65B5531094EDC0C5F3A5EB46 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-21"
      version             = "1.0"

      hash                = "10b88dc57f20704b3d3d1c7b6cebe31052ef712e0366b7feffd83c2ff5ef3131"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Code 7 Eventclothing GmbH"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "65:b5:53:10:94:ed:c0:c5:f3:a5:eb:46"
      cert_thumbprint     = "D229315A65A625B7ABEEF9B1C0FAF487D061B5B7"
      cert_valid_from     = "2025-02-21"
      cert_valid_to       = "2026-02-22"

      country             = "AT"
      state               = "Tirol"
      locality            = "Reutte"
      email               = "???"
      rdn_serial_number   = "310473d"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "65:b5:53:10:94:ed:c0:c5:f3:a5:eb:46"
      )
}
