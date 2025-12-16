import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_04CF28D1A98360DF407FBED6 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-06"
      version             = "1.0"

      hash                = "7e6dfeb5e87453cb9999e592d76f8b5ba4bb4d0e5c6eeb6f12de03fa17801a47"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC NOVOTEK"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "04:cf:28:d1:a9:83:60:df:40:7f:be:d6"
      cert_thumbprint     = "A774E9D46CB669A2566C340D343C305AA8D8A8F2"
      cert_valid_from     = "2025-10-06"
      cert_valid_to       = "2026-07-17"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "04:cf:28:d1:a9:83:60:df:40:7f:be:d6"
      )
}
