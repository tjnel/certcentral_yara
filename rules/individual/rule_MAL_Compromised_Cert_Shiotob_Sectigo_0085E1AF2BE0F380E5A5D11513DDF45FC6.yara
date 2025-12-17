import "pe"

rule MAL_Compromised_Cert_Shiotob_Sectigo_0085E1AF2BE0F380E5A5D11513DDF45FC6 {
   meta:
      description         = "Detects Shiotob with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-09-01"
      version             = "1.0"

      hash                = "93aa642ec749cc6b093b90d06d9a87843c76d3a8406620c8296a97515ea9954a"
      malware             = "Shiotob"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Makke Digital Works"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:85:e1:af:2b:e0:f3:80:e5:a5:d1:15:13:dd:f4:5f:c6"
      cert_thumbprint     = "D66181CC42B1C9B7A7B480FB5A38CD38ADD04FCF"
      cert_valid_from     = "2020-09-01"
      cert_valid_to       = "2021-09-01"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "Helsinki"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:85:e1:af:2b:e0:f3:80:e5:a5:d1:15:13:dd:f4:5f:c6"
      )
}
