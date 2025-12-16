import "pe"

rule MAL_Compromised_Cert_VenomRat_GoGetSSL_01102CCEFAAD00D62684635B105FFC57 {
   meta:
      description         = "Detects VenomRat with compromised cert (GoGetSSL)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-21"
      version             = "1.0"

      hash                = "6f9d8640168fb34aff3b829d7f08246eb772228c37bcb0f5b2621260704df159"
      malware             = "VenomRat"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Atik Mekanik Endüstriyel İzolasyon Mühendislik Dış Ticaret A.Ş"
      cert_issuer_short   = "GoGetSSL"
      cert_issuer         = "GoGetSSL G4 CS RSA4096 SHA256 2022 CA-1"
      cert_serial         = "01:10:2c:ce:fa:ad:00:d6:26:84:63:5b:10:5f:fc:57"
      cert_thumbprint     = "61656971F3472069AF5080454C02A6D76A4D337A"
      cert_valid_from     = "2025-02-21"
      cert_valid_to       = "2026-02-20"

      country             = "TR"
      state               = "İstanbul"
      locality            = "Beykoz"
      email               = "???"
      rdn_serial_number   = "391452-5"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GoGetSSL G4 CS RSA4096 SHA256 2022 CA-1" and
         sig.serial == "01:10:2c:ce:fa:ad:00:d6:26:84:63:5b:10:5f:fc:57"
      )
}
