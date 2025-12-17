import "pe"

rule MAL_Compromised_Cert_FlawedAmmyy_GlobalSign_4484F1C5B6A72DFEC0E1CA55 {
   meta:
      description         = "Detects FlawedAmmyy with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-06-13"
      version             = "1.0"

      hash                = "5be959722d8cd4bfd6f88a4901f44f9a43aa875f55ec90e6a91a36a7186cd4a5"
      malware             = "FlawedAmmyy"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "TAIM LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "44:84:f1:c5:b6:a7:2d:fe:c0:e1:ca:55"
      cert_thumbprint     = "4CB87577FA5B91346CCE30FB9FF3139D46DE3361"
      cert_valid_from     = "2023-06-13"
      cert_valid_to       = "2024-06-13"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1237700338303"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "44:84:f1:c5:b6:a7:2d:fe:c0:e1:ca:55"
      )
}
