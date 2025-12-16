import "pe"

rule MAL_Compromised_Cert_RemcosRAT_Sectigo_1614EF66B2C4B886E71A93DD34869F48 {
   meta:
      description         = "Detects RemcosRAT with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-05-31"
      version             = "1.0"

      hash                = "818bd67db5fe30f5cfdab861f996f30fa20427e3e1aa65ffe6d98f6c7af7558d"
      malware             = "RemcosRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SHIRT AND CUFF LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "16:14:ef:66:b2:c4:b8:86:e7:1a:93:dd:34:86:9f:48"
      cert_thumbprint     = "8C83C0DF901B2DEBEC74DBA17696D89E3428786D"
      cert_valid_from     = "2022-05-31"
      cert_valid_to       = "2023-05-31"

      country             = "GB"
      state               = "Berkshire"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "16:14:ef:66:b2:c4:b8:86:e7:1a:93:dd:34:86:9f:48"
      )
}
