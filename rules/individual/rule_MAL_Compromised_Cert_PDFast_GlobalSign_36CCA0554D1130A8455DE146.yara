import "pe"

rule MAL_Compromised_Cert_PDFast_GlobalSign_36CCA0554D1130A8455DE146 {
   meta:
      description         = "Detects PDFast with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-04-16"
      version             = "1.0"

      hash                = "6ef80b596195ac002f072811bb2c73e6d45b8f914ada6d1e613ad9abe14bc09c"
      malware             = "PDFast"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "IBRAHIM MANNAN LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "36:cc:a0:55:4d:11:30:a8:45:5d:e1:46"
      cert_thumbprint     = "5AD122B091C21EB546DFD20086D266E0E8429ABF"
      cert_valid_from     = "2024-04-16"
      cert_valid_to       = "2025-04-17"

      country             = "US"
      state               = "Florida"
      locality            = "Saint Petersburg"
      email               = "farhadikhlaq483@gmail.com"
      rdn_serial_number   = "L23000274215"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "36:cc:a0:55:4d:11:30:a8:45:5d:e1:46"
      )
}
