import "pe"

rule MAL_Compromised_Cert_ChromeLoader_GlobalSign_762249DCE6ECB54903DFA0A0 {
   meta:
      description         = "Detects ChromeLoader with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-19"
      version             = "1.0"

      hash                = "cc3c07ee3ade28f39fd20035043acd8c631449e9da5c38c03c02557348e190fa"
      malware             = "ChromeLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "INNOVA MEDIA internetne storitve d.o.o."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "76:22:49:dc:e6:ec:b5:49:03:df:a0:a0"
      cert_thumbprint     = "62AFB2B59E43149CBA03B0812784D48D4A5F71F1"
      cert_valid_from     = "2024-06-19"
      cert_valid_to       = "2026-05-22"

      country             = "SI"
      state               = "Šempeter-Vrtojba"
      locality            = "Šempeter pri Gorici"
      email               = "???"
      rdn_serial_number   = "6466885000"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "76:22:49:dc:e6:ec:b5:49:03:df:a0:a0"
      )
}
