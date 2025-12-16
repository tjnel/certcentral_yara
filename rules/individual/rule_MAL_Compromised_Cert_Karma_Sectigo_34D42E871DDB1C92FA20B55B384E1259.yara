import "pe"

rule MAL_Compromised_Cert_Karma_Sectigo_34D42E871DDB1C92FA20B55B384E1259 {
   meta:
      description         = "Detects Karma with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-08-31"
      version             = "1.0"

      hash                = "4dec9a9044631caef283c7f39a576e4e5c1cc1e6a97ce5c60936a3a3d0097818"
      malware             = "Karma"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "VENS CORP"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "34:d4:2e:87:1d:db:1c:92:fa:20:b5:5b:38:4e:12:59"
      cert_thumbprint     = "B8C6E51400B10B718DB1D622E247007195356E9F"
      cert_valid_from     = "2021-08-31"
      cert_valid_to       = "2022-08-31"

      country             = "FR"
      state               = "Île-de-France"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "34:d4:2e:87:1d:db:1c:92:fa:20:b5:5b:38:4e:12:59"
      )
}
