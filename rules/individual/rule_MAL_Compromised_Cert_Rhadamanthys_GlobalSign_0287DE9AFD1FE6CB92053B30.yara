import "pe"

rule MAL_Compromised_Cert_Rhadamanthys_GlobalSign_0287DE9AFD1FE6CB92053B30 {
   meta:
      description         = "Detects Rhadamanthys with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-11"
      version             = "1.0"

      hash                = "545812664008d0b35cf61c15c79526b1d5d05aef886a3f85c9056570fbf13933"
      malware             = "Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "MOTTO IMPEX LLP"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "02:87:de:9a:fd:1f:e6:cb:92:05:3b:30"
      cert_thumbprint     = "8A0D7827D9E04C872F022847D519871E1569A5F4"
      cert_valid_from     = "2025-07-11"
      cert_valid_to       = "2026-07-12"

      country             = "IN"
      state               = "Bihar"
      locality            = "Samastipur"
      email               = "yogeshpatel.motto@gmail.com"
      rdn_serial_number   = "UDYAM-BR-30-0046322"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "02:87:de:9a:fd:1f:e6:cb:92:05:3b:30"
      )
}
