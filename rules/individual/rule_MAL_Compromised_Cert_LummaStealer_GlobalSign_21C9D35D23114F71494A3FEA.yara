import "pe"

rule MAL_Compromised_Cert_LummaStealer_GlobalSign_21C9D35D23114F71494A3FEA {
   meta:
      description         = "Detects LummaStealer with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-12"
      version             = "1.0"

      hash                = "c6e3855f6893092020a2dce35e30869d96a7922f2b805bbdf081eec97cbba62b"
      malware             = "LummaStealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "S.R.L. CONSTUDIO GRUP"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "21:c9:d3:5d:23:11:4f:71:49:4a:3f:ea"
      cert_thumbprint     = "346EA81E7E518EC2BF5DE0AF8A63A0558A39CC1D"
      cert_valid_from     = "2025-03-12"
      cert_valid_to       = "2026-03-13"

      country             = "MD"
      state               = "Chișinău"
      locality            = "Chișinău"
      email               = "???"
      rdn_serial_number   = "1010600029333"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "21:c9:d3:5d:23:11:4f:71:49:4a:3f:ea"
      )
}
