import "pe"

rule MAL_Compromised_Cert_PDFast_GlobalSign_6F967286B3DB0B954F9A84E7 {
   meta:
      description         = "Detects PDFast with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-30"
      version             = "1.0"

      hash                = "efea4b2f5df566c507e96f11a8a74b00724015cac86e5d08b85f6c31d2284413"
      malware             = "PDFast"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SHINE YOUR GUTS (SMC-PRIVATE) LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 CodeSigning CA 2020"
      cert_serial         = "6f:96:72:86:b3:db:0b:95:4f:9a:84:e7"
      cert_thumbprint     = "F59F7E5AD23D964F614D0A7549F5D49EB166EFEE"
      cert_valid_from     = "2024-09-30"
      cert_valid_to       = "2025-10-01"

      country             = "PK"
      state               = "Punjab"
      locality            = "Lahore"
      email               = "REEMA77IK@GMAIL.COM"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 CodeSigning CA 2020" and
         sig.serial == "6f:96:72:86:b3:db:0b:95:4f:9a:84:e7"
      )
}
