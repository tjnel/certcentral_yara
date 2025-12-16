import "pe"

rule MAL_Compromised_Cert_WebCompanion_Unknown_397040964E49A912BD2B2EAC53D98363 {
   meta:
      description         = "Detects WebCompanion with compromised cert (Unknown)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2019-08-27"
      version             = "1.0"

      hash                = "bd35c7a5f4b699d42563e773d234c3fba32577673f35aeb274893d4925cb5f64"
      malware             = "WebCompanion"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "BULLY UNITY LTD"
      cert_issuer_short   = "Unknown"
      cert_issuer         = "Domain The Net Technologies Ltd CA for Code Signing R2"
      cert_serial         = "39:70:40:96:4e:49:a9:12:bd:2b:2e:ac:53:d9:83:63"
      cert_thumbprint     = "93721992237099EC415EDBF574FA028FB7A08020"
      cert_valid_from     = "2019-08-27"
      cert_valid_to       = "2020-08-26"

      country             = "IL"
      state               = "Israel"
      locality            = "Jerusalem"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Domain The Net Technologies Ltd CA for Code Signing R2" and
         sig.serial == "39:70:40:96:4e:49:a9:12:bd:2b:2e:ac:53:d9:83:63"
      )
}
