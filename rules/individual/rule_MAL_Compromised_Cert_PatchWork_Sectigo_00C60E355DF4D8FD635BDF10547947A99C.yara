import "pe"

rule MAL_Compromised_Cert_PatchWork_Sectigo_00C60E355DF4D8FD635BDF10547947A99C {
   meta:
      description         = "Detects PatchWork with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-05-10"
      version             = "1.0"

      hash                = "f23219ecdaf0a4adceed01b9e363f66ff16b0ce0b269763d0cfc7309eaba44f7"
      malware             = "PatchWork"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "GJT AUTOMOTIVE LTD"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA 2"
      cert_serial         = "00:c6:0e:35:5d:f4:d8:fd:63:5b:df:10:54:79:47:a9:9c"
      cert_thumbprint     = "380DE3C9CC3ADB85573FC8E8ACD8E855B13FEE54"
      cert_valid_from     = "2023-05-10"
      cert_valid_to       = "2024-05-09"

      country             = "GB"
      state               = "Lancashire"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA 2" and
         sig.serial == "00:c6:0e:35:5d:f4:d8:fd:63:5b:df:10:54:79:47:a9:9c"
      )
}
