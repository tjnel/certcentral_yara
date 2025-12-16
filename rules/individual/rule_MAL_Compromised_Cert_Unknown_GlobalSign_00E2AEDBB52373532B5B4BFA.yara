import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_00E2AEDBB52373532B5B4BFA {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-06"
      version             = "1.0"

      hash                = "0966555bd577a1a3d45655422d0d41df77eb1834b93a56288ed336593b402d0e"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "KVK Montage ApS"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "00:e2:ae:db:b5:23:73:53:2b:5b:4b:fa"
      cert_thumbprint     = "0AC087BD7E421C48670C5A51F3C7C78C39DF383D"
      cert_valid_from     = "2024-12-06"
      cert_valid_to       = "2025-12-07"

      country             = "DK"
      state               = "Hovedstaden"
      locality            = "Frederikssund"
      email               = "???"
      rdn_serial_number   = "32842097"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "00:e2:ae:db:b5:23:73:53:2b:5b:4b:fa"
      )
}
