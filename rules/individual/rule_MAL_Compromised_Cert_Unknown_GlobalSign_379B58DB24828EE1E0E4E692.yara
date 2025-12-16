import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_379B58DB24828EE1E0E4E692 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-09-22"
      version             = "1.0"

      hash                = "69288eeb78f736b316e154f85755320c052fcd0706d252f47213cb49d5673382"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "STALKER LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "37:9b:58:db:24:82:8e:e1:e0:e4:e6:92"
      cert_thumbprint     = "A0C2673847F02555D5EFE92A065762CA2457848F"
      cert_valid_from     = "2023-09-22"
      cert_valid_to       = "2024-09-22"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "37:9b:58:db:24:82:8e:e1:e0:e4:e6:92"
      )
}
