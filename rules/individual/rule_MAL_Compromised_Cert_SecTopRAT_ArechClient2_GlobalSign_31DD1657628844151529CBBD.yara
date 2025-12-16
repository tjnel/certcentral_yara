import "pe"

rule MAL_Compromised_Cert_SecTopRAT_ArechClient2_GlobalSign_31DD1657628844151529CBBD {
   meta:
      description         = "Detects SecTopRAT,ArechClient2 with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-17"
      version             = "1.0"

      hash                = "383af7126e2e28748b4b75c66cc3406933a935931185d37b672a033cb193a26c"
      malware             = "SecTopRAT,ArechClient2"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "LLC YUSAL"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "31:dd:16:57:62:88:44:15:15:29:cb:bd"
      cert_thumbprint     = "C54D949A1005756186AA150C94071F3CAA4ECAE9"
      cert_valid_from     = "2025-01-17"
      cert_valid_to       = "2026-01-18"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "ysul569@mail.ru"
      rdn_serial_number   = "1196313074726"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "31:dd:16:57:62:88:44:15:15:29:cb:bd"
      )
}
