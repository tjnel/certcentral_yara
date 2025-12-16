import "pe"

rule MAL_Compromised_Cert_PDFast_GlobalSign_08B4249EC5131AE0856893BB {
   meta:
      description         = "Detects PDFast with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-20"
      version             = "1.0"

      hash                = "4f3a8d56a20474eb3962457689614d2360b99f6d034a60d207550abac99896a2"
      malware             = "PDFast"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Called Sparkline LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "08:b4:24:9e:c5:13:1a:e0:85:68:93:bb"
      cert_thumbprint     = "B30F77A8BC06AADA08B76E9176C3C15E7C9C49FF"
      cert_valid_from     = "2024-12-20"
      cert_valid_to       = "2025-12-21"

      country             = "US"
      state               = "Texas"
      locality            = "Austin"
      email               = "fm760984@gmail.com"
      rdn_serial_number   = "0805421133"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "08:b4:24:9e:c5:13:1a:e0:85:68:93:bb"
      )
}
