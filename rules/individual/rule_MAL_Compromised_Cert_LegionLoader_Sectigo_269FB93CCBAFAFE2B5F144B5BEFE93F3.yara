import "pe"

rule MAL_Compromised_Cert_LegionLoader_Sectigo_269FB93CCBAFAFE2B5F144B5BEFE93F3 {
   meta:
      description         = "Detects LegionLoader with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-11-17"
      version             = "1.0"

      hash                = "fa60e517ee864bed74a9cdf0dc41efe86190a442df1ffda8b4f59f9890f0c22a"
      malware             = "LegionLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "GALAKTIKA, OOO"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "26:9f:b9:3c:cb:af:af:e2:b5:f1:44:b5:be:fe:93:f3"
      cert_thumbprint     = "107A38A1D2DE225F43927B20016FDD7046B84524"
      cert_valid_from     = "2020-11-17"
      cert_valid_to       = "2021-11-17"

      country             = "RU"
      state               = "???"
      locality            = "St petersburg"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "26:9f:b9:3c:cb:af:af:e2:b5:f1:44:b5:be:fe:93:f3"
      )
}
