import "pe"

rule MAL_Compromised_Cert_PDFast_GlobalSign_36CC39AA22030F7FA71592F8 {
   meta:
      description         = "Detects PDFast with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-09"
      version             = "1.0"

      hash                = "103c8764f8af476e8801c03a03969f388133b8586de93b13fcba52bf1772c8e5"
      malware             = "PDFast"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SEELIV (SMC-PRIVATE) LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "36:cc:39:aa:22:03:0f:7f:a7:15:92:f8"
      cert_thumbprint     = "77E3B1710323F25812A7AF8D2A6A5C6A743DC25F"
      cert_valid_from     = "2024-10-09"
      cert_valid_to       = "2025-10-10"

      country             = "PK"
      state               = "Punjab"
      locality            = "Multan"
      email               = "farhadikhlaq483@gmail.com"
      rdn_serial_number   = "0175853"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "36:cc:39:aa:22:03:0f:7f:a7:15:92:f8"
      )
}
