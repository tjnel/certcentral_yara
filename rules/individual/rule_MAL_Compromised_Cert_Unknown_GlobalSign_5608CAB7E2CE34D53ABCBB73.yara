import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_5608CAB7E2CE34D53ABCBB73 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-20"
      version             = "1.0"

      hash                = "92d457b286fb63d2f5ec9413fd234643448c5f8d2c0763e43ed5cf27ab47eb02"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Ataleo GmbH"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "56:08:ca:b7:e2:ce:34:d5:3a:bc:bb:73"
      cert_thumbprint     = "BE7156BD07DD7F72521FAE4A3D6F46C48DD2CE9E"
      cert_valid_from     = "2024-12-20"
      cert_valid_to       = "2026-12-21"

      country             = "AT"
      state               = "Wien"
      locality            = "Wien"
      email               = "admin@ataleogmbh.com"
      rdn_serial_number   = "550807k"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "56:08:ca:b7:e2:ce:34:d5:3a:bc:bb:73"
      )
}
