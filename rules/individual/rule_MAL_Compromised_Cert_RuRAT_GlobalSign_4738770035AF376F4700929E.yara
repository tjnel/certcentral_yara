import "pe"

rule MAL_Compromised_Cert_RuRAT_GlobalSign_4738770035AF376F4700929E {
   meta:
      description         = "Detects RuRAT with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-19"
      version             = "1.0"

      hash                = "3f01b255f64dae77e6bdeaf917fe88c0bad973fbda6e785ccd5bfca9637c6870"
      malware             = "RuRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Guang Zhou Uitin Electronic Tech. Ltm Co.,"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "47:38:77:00:35:af:37:6f:47:00:92:9e"
      cert_thumbprint     = "5AC3640132EE86B9F812FE04A67D05F2A7188F04"
      cert_valid_from     = "2025-03-19"
      cert_valid_to       = "2026-03-20"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Guangzhou"
      email               = "???"
      rdn_serial_number   = "91440115MA59AMXP30"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "47:38:77:00:35:af:37:6f:47:00:92:9e"
      )
}
