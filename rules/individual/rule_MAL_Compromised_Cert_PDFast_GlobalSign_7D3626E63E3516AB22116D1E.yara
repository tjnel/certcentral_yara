import "pe"

rule MAL_Compromised_Cert_PDFast_GlobalSign_7D3626E63E3516AB22116D1E {
   meta:
      description         = "Detects PDFast with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-04-09"
      version             = "1.0"

      hash                = "a7f0794872bc5d0fedcf6161c7002e0d9fc7e23cd8d390e0327db7c010dd7a1a"
      malware             = "PDFast"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "AL STARE LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "7d:36:26:e6:3e:35:16:ab:22:11:6d:1e"
      cert_thumbprint     = "2DEFD4D6CBB10B7AFD9B5A3DBD61E756549EE3CB"
      cert_valid_from     = "2024-04-09"
      cert_valid_to       = "2025-04-10"

      country             = "US"
      state               = "TEXAS"
      locality            = "AUSTIN"
      email               = "fm760984@gmail.com"
      rdn_serial_number   = "0805239913"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "7d:36:26:e6:3e:35:16:ab:22:11:6d:1e"
      )
}
