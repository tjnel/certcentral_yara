import "pe"

rule MAL_Compromised_Cert_Rhadamanthys_GlobalSign_5CF47C5F8A6B09AD2C71EEB9 {
   meta:
      description         = "Detects Rhadamanthys with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-20"
      version             = "1.0"

      hash                = "e0e0b3d2890053cbdf84d6c3177e267d8f767f4b2b6d6e5fb2de5860b0a09ee2"
      malware             = "Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "AJMERA FAB INDIA PRIVATE LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "5c:f4:7c:5f:8a:6b:09:ad:2c:71:ee:b9"
      cert_thumbprint     = "4D5557739E78C96707F793213ECA3D3BCA232C5C"
      cert_valid_from     = "2025-03-20"
      cert_valid_to       = "2026-03-21"

      country             = "IN"
      state               = "Rajasthan"
      locality            = "Jaipur"
      email               = "gittapod.42@gmail.com"
      rdn_serial_number   = "U74999RJ2016PTC056595"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "5c:f4:7c:5f:8a:6b:09:ad:2c:71:ee:b9"
      )
}
