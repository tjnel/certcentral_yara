import "pe"

rule MAL_Compromised_Cert_FakeBat_SSL_com_5556D68E17AD6356D0B6DBEFC087FDE2 {
   meta:
      description         = "Detects FakeBat with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-01-26"
      version             = "1.0"

      hash                = "6ba4231e13c7ca51dbf672e477e633f83ba59e1392b9755c301c14abe35cdf61"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "QRC Holdings Limited"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "55:56:d6:8e:17:ad:63:56:d0:b6:db:ef:c0:87:fd:e2"
      cert_thumbprint     = "F721E4E6A432929134F137AF2727CFA76FDC6826"
      cert_valid_from     = "2024-01-26"
      cert_valid_to       = "2025-01-25"

      country             = "GB"
      state               = "???"
      locality            = "Royston"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "55:56:d6:8e:17:ad:63:56:d0:b6:db:ef:c0:87:fd:e2"
      )
}
