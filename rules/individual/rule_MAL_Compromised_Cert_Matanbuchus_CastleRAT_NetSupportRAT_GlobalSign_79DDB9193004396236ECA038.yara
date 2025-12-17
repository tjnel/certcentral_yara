import "pe"

rule MAL_Compromised_Cert_Matanbuchus_CastleRAT_NetSupportRAT_GlobalSign_79DDB9193004396236ECA038 {
   meta:
      description         = "Detects Matanbuchus,CastleRAT,NetSupportRAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-11"
      version             = "1.0"

      hash                = "ed748bfb18ebd9e83b0b694894f34fdd47a8e615dadd54cf922f350085d1a7e0"
      malware             = "Matanbuchus,CastleRAT,NetSupportRAT"
      malware_type        = "Initial access tool"
      malware_notes       = "In this instance of the malware, it was used to drop both CastleRAT malware and NetSupport."

      signer              = "NAVRNGE RECOVERY SERVICES PRIVATE LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "79:dd:b9:19:30:04:39:62:36:ec:a0:38"
      cert_thumbprint     = "FF8014C820D337E3844AFF84CB61C4748888AB28"
      cert_valid_from     = "2025-07-11"
      cert_valid_to       = "2026-07-12"

      country             = "IN"
      state               = "Bihar"
      locality            = "Samastipur"
      email               = "navrngerecoveryservices@gmail.com"
      rdn_serial_number   = "UDYAM-BR-30-0066580"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "79:dd:b9:19:30:04:39:62:36:ec:a0:38"
      )
}
