import "pe"

rule MAL_Compromised_Cert_CobaltStrike_GlobalSign_38EBC2945F2798C8FBB0FBB4 {
   meta:
      description         = "Detects CobaltStrike with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-14"
      version             = "1.0"

      hash                = "c2cb38569e885d47deb9b3869c60ab2d978a5a244e238777d6156c0c486cc879"
      malware             = "CobaltStrike"
      malware_type        = "Remote access tool"
      malware_notes       = "A commercial red-teaming product which is weaponized by a wide range of cybercriminals: https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"

      signer              = "KINDATECH SOLUTIONS LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "38:eb:c2:94:5f:27:98:c8:fb:b0:fb:b4"
      cert_thumbprint     = "D1D88A32CF201EA8CB3F6E2A93034B8E5ACDF8A0"
      cert_valid_from     = "2025-01-14"
      cert_valid_to       = "2026-01-15"

      country             = "KE"
      state               = "Nakuru"
      locality            = "Nakuru"
      email               = "???"
      rdn_serial_number   = "CPR/2009/7526"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "38:eb:c2:94:5f:27:98:c8:fb:b0:fb:b4"
      )
}
