import "pe"

rule MAL_Compromised_Cert_Rhadamanthys_SSL_com_3D514DDBCFB84255F2424AE9530FBF6A {
   meta:
      description         = "Detects Rhadamanthys with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-07-28"
      version             = "1.0"

      hash                = "8bedd04e21578832c2e63bc28f20ebdd2c4b1b5a34e7740804b844ecc394d351"
      malware             = "Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "Phoenix Ornamentals Limited"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "3d:51:4d:db:cf:b8:42:55:f2:42:4a:e9:53:0f:bf:6a"
      cert_thumbprint     = "4D4521CECE024D2B1530B619E5208518374E189F"
      cert_valid_from     = "2023-07-28"
      cert_valid_to       = "2024-07-27"

      country             = "GB"
      state               = "???"
      locality            = "Aylesford"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "3d:51:4d:db:cf:b8:42:55:f2:42:4a:e9:53:0f:bf:6a"
      )
}
