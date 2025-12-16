import "pe"

rule MAL_Compromised_Cert_Lazarus_Sectigo_00913BA16962CD7EEE25965A6D0EEFFA10 {
   meta:
      description         = "Detects Lazarus with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2019-07-12"
      version             = "1.0"

      hash                = "081d1739422bf050755e6af269a717681274821cea8becb0962d4db61869c5d6"
      malware             = "Lazarus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "JMT TRADING GROUP INC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:91:3b:a1:69:62:cd:7e:ee:25:96:5a:6d:0e:ef:fa:10"
      cert_thumbprint     = "079AEB295C8E27AC8D9BE79C8B0AAF66A0EF15DE"
      cert_valid_from     = "2019-07-12"
      cert_valid_to       = "2020-07-11"

      country             = "US"
      state               = "CALIFORNIA"
      locality            = "ROWLAND HEIGHTS"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:91:3b:a1:69:62:cd:7e:ee:25:96:5a:6d:0e:ef:fa:10"
      )
}
