import "pe"

rule MAL_Compromised_Cert_AureliaLoader_GlobalSign_4663D820BE745ECD017B73FC {
   meta:
      description         = "Detects AureliaLoader with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-23"
      version             = "1.0"

      hash                = "2cee9b72969beb59dd8441a637fdc8275afe13dfb6356e24a1daa1f77c555639"
      malware             = "AureliaLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC Organic"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "46:63:d8:20:be:74:5e:cd:01:7b:73:fc"
      cert_thumbprint     = "5FF149DDE0978C86386F244CB7C9CC0FAE7BF24C"
      cert_valid_from     = "2025-04-23"
      cert_valid_to       = "2026-04-24"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1205000018992"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "46:63:d8:20:be:74:5e:cd:01:7b:73:fc"
      )
}
