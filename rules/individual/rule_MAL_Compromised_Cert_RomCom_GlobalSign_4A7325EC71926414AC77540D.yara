import "pe"

rule MAL_Compromised_Cert_RomCom_GlobalSign_4A7325EC71926414AC77540D {
   meta:
      description         = "Detects RomCom with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-22"
      version             = "1.0"

      hash                = "3c8b7034c015aed1c0c1d287dc5a8fe3871fa5def570f4cef43e1411de864e86"
      malware             = "RomCom"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Guangzhou VW Science and Technology Ltd. Co"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "4a:73:25:ec:71:92:64:14:ac:77:54:0d"
      cert_thumbprint     = "24BD135B92A95C0E7F9967F6372BBE4BC99D9F84"
      cert_valid_from     = "2024-11-22"
      cert_valid_to       = "2025-11-23"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Guangzhou"
      email               = "???"
      rdn_serial_number   = "91440101MA59Q6R47Q"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "4a:73:25:ec:71:92:64:14:ac:77:54:0d"
      )
}
