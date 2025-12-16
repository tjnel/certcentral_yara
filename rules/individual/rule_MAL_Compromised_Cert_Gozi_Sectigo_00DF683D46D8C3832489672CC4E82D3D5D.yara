import "pe"

rule MAL_Compromised_Cert_Gozi_Sectigo_00DF683D46D8C3832489672CC4E82D3D5D {
   meta:
      description         = "Detects Gozi with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-11-12"
      version             = "1.0"

      hash                = "7a5e4fd35a1a636ef1beb7e62cc647d7e63f5c7aadd2aa1a49d49c81183aca93"
      malware             = "Gozi"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Osatokio Oy"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:df:68:3d:46:d8:c3:83:24:89:67:2c:c4:e8:2d:3d:5d"
      cert_thumbprint     = "2119AB338EC2589199A36B0F1793D17A74B7CF2E"
      cert_valid_from     = "2020-11-12"
      cert_valid_to       = "2021-11-12"

      country             = "FI"
      state               = "???"
      locality            = "Vantaa"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:df:68:3d:46:d8:c3:83:24:89:67:2c:c4:e8:2d:3d:5d"
      )
}
