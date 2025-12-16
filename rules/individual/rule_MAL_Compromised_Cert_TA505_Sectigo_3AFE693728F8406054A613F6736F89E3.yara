import "pe"

rule MAL_Compromised_Cert_TA505_Sectigo_3AFE693728F8406054A613F6736F89E3 {
   meta:
      description         = "Detects TA505 with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-08-07"
      version             = "1.0"

      hash                = "d98bdf3508763fe0df177ef696f5bf8de7ff7c7dc68bb04a14a95ec28528c3f9"
      malware             = "TA505"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ROB ALDERMAN FITNESS LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "3a:fe:69:37:28:f8:40:60:54:a6:13:f6:73:6f:89:e3"
      cert_thumbprint     = "89528E9005A635BCEE8DA5539E71C5FC4F839F50"
      cert_valid_from     = "2020-08-07"
      cert_valid_to       = "2023-08-07"

      country             = "GB"
      state               = "BRISTOL"
      locality            = "BRISTOL"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "3a:fe:69:37:28:f8:40:60:54:a6:13:f6:73:6f:89:e3"
      )
}
