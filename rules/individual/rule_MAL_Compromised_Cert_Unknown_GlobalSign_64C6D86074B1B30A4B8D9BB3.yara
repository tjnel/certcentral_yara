import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_64C6D86074B1B30A4B8D9BB3 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-10-26"
      version             = "1.0"

      hash                = "ffac4fd01545cacc92fde4f8cdeb45eb3786262670a67958b85862dfcba073d7"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "UTILITY ACCESS (SMC-PRIVATE) LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "64:c6:d8:60:74:b1:b3:0a:4b:8d:9b:b3"
      cert_thumbprint     = "97793FF580486BBD0CE73872289F554D7A036DA5"
      cert_valid_from     = "2023-10-26"
      cert_valid_to       = "2024-10-26"

      country             = "PK"
      state               = "Punjab"
      locality            = "Multan"
      email               = "maliksabirsabir483@gmail.com"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "64:c6:d8:60:74:b1:b3:0a:4b:8d:9b:b3"
      )
}
