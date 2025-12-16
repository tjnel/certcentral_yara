import "pe"

rule MAL_Compromised_Cert_Servhelper_Sectigo_00EDE6CFBF9FA18337B0FDB49C1F693020 {
   meta:
      description         = "Detects Servhelper with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2019-04-11"
      version             = "1.0"

      hash                = "fd2516f5a8dd9eaddac65f4bd8ae4ed6cba9e115ebe88c3f6d2f5e2cdd5e20a6"
      malware             = "Servhelper"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "START ARCHITECTURE LTD"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:ed:e6:cf:bf:9f:a1:83:37:b0:fd:b4:9c:1f:69:30:20"
      cert_thumbprint     = "A99B52E0999990C2EB24D1309DE7D4E522937080"
      cert_valid_from     = "2019-04-11"
      cert_valid_to       = "2020-04-10"

      country             = "GB"
      state               = "WARWICK"
      locality            = "WARWICK"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:ed:e6:cf:bf:9f:a1:83:37:b0:fd:b4:9c:1f:69:30:20"
      )
}
