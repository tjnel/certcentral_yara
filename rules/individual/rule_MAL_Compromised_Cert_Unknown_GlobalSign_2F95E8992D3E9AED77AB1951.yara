import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_2F95E8992D3E9AED77AB1951 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-24"
      version             = "1.0"

      hash                = "d9a9685b8afc676497ee18a0bb6775dfebb7a1ca867967530e92800ddcb309ee"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "MASTER SGDN BAU GMBH"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "2f:95:e8:99:2d:3e:9a:ed:77:ab:19:51"
      cert_thumbprint     = "3D4909FB24D9660D6B9AD298E2A4E6F3EB642BD4"
      cert_valid_from     = "2024-09-24"
      cert_valid_to       = "2026-09-25"

      country             = "AT"
      state               = "Wien"
      locality            = "Wien"
      email               = "admin@mastersgdnbau.com"
      rdn_serial_number   = "612294h"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "2f:95:e8:99:2d:3e:9a:ed:77:ab:19:51"
      )
}
