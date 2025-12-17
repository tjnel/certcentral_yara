import "pe"

rule MAL_Compromised_Cert_Traffer_GlobalSign_3A352958B8D4FDAFE1C6B8E8 {
   meta:
      description         = "Detects Traffer with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-16"
      version             = "1.0"

      hash                = "99b8ad6a13f701f9fb9e4a2279c6f724cf6bb9476246c9b77626c3db90522071"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "UTTAM AGRITECH PRIVATE LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "3a:35:29:58:b8:d4:fd:af:e1:c6:b8:e8"
      cert_thumbprint     = "908BB7F8704C44FCDE95D602E2C4DA3077304255"
      cert_valid_from     = "2025-07-16"
      cert_valid_to       = "2026-07-17"

      country             = "IN"
      state               = "Rajasthan"
      locality            = "Jaipur"
      email               = "uttamagritechindia@gmail.com"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "3a:35:29:58:b8:d4:fd:af:e1:c6:b8:e8"
      )
}
