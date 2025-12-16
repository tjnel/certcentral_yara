import "pe"

rule MAL_Compromised_Cert_Hive_DigiCert_06DF5C318759D6EA9D090BFB2FAF1D94 {
   meta:
      description         = "Detects Hive with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-10-18"
      version             = "1.0"

      hash                = "47dbb2594cd5eb7015ef08b7fb803cd5adc1a1fbe4849dc847c0940f1ccace35"
      malware             = "Hive"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SpiffyTech Inc."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "06:df:5c:31:87:59:d6:ea:9d:09:0b:fb:2f:af:1d:94"
      cert_thumbprint     = "4418E9A7AAB0909FA611985804416B1AAF41E175"
      cert_valid_from     = "2021-10-18"
      cert_valid_to       = "2022-10-05"

      country             = "CA"
      state               = "British Columbia"
      locality            = "Vancouver"
      email               = "???"
      rdn_serial_number   = "1000712-9"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "06:df:5c:31:87:59:d6:ea:9d:09:0b:fb:2f:af:1d:94"
      )
}
