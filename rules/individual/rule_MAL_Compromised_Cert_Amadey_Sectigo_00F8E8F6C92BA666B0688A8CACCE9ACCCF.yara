import "pe"

rule MAL_Compromised_Cert_Amadey_Sectigo_00F8E8F6C92BA666B0688A8CACCE9ACCCF {
   meta:
      description         = "Detects Amadey with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-04-16"
      version             = "1.0"

      hash                = "7788316d7c265de3857cd869311e3227bad84465e2ae93f95fa5eeada4bdddd0"
      malware             = "Amadey"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "5 th Dimension LTD Oy"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:f8:e8:f6:c9:2b:a6:66:b0:68:8a:8c:ac:ce:9a:cc:cf"
      cert_thumbprint     = "135B79175F959AEFF0C7D4C7C705CD8141C0C03B"
      cert_valid_from     = "2021-04-16"
      cert_valid_to       = "2022-04-16"

      country             = "FI"
      state               = "???"
      locality            = "Helsinki"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:f8:e8:f6:c9:2b:a6:66:b0:68:8a:8c:ac:ce:9a:cc:cf"
      )
}
