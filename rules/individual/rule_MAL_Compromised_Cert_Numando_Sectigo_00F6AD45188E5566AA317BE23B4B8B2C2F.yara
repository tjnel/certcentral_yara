import "pe"

rule MAL_Compromised_Cert_Numando_Sectigo_00F6AD45188E5566AA317BE23B4B8B2C2F {
   meta:
      description         = "Detects Numando with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-03-22"
      version             = "1.0"

      hash                = "b535f3c56749c532d29440fc0a446e3d5a46c294996af8c2992273e2499222e0"
      malware             = "Numando"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Gary Kramlich"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:f6:ad:45:18:8e:55:66:aa:31:7b:e2:3b:4b:8b:2c:2f"
      cert_thumbprint     = "ADFA744AA074FB5DC57EE6445A3E18D606C7BF96"
      cert_valid_from     = "2021-03-22"
      cert_valid_to       = "2024-03-21"

      country             = "US"
      state               = "Wisconsin"
      locality            = "MILWAUKEE"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:f6:ad:45:18:8e:55:66:aa:31:7b:e2:3b:4b:8b:2c:2f"
      )
}
