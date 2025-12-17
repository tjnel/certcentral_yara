import "pe"

rule MAL_Compromised_Cert_Wagmi_Traffer_Team_GlobalSign_75D0F25D4BFA30C1461F3721 {
   meta:
      description         = "Detects Wagmi Traffer Team with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-14"
      version             = "1.0"

      hash                = "dfe856eed36f45524421ba2dda6cdbf9b048e900a87eb74daf76e76dc8b157dd"
      malware             = "Wagmi Traffer Team"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "HUNG KHIEM TRANSPORT COMPANY LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "75:d0:f2:5d:4b:fa:30:c1:46:1f:37:21"
      cert_thumbprint     = ""
      cert_valid_from     = "2025-04-14"
      cert_valid_to       = "2026-04-15"

      country             = "VN"
      state               = "Ninh Binh"
      locality            = "Ninh Binh"
      email               = ""
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "75:d0:f2:5d:4b:fa:30:c1:46:1f:37:21"
      )
}
