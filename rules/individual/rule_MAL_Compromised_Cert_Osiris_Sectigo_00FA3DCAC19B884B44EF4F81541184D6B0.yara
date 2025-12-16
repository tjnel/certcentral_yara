import "pe"

rule MAL_Compromised_Cert_Osiris_Sectigo_00FA3DCAC19B884B44EF4F81541184D6B0 {
   meta:
      description         = "Detects Osiris with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-10-27"
      version             = "1.0"

      hash                = "bf9eb06db25ea1d3138b8e19a18d248df56a04200f9e54edfed850d018d2bb62"
      malware             = "Osiris"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Unicom Ltd"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:fa:3d:ca:c1:9b:88:4b:44:ef:4f:81:54:11:84:d6:b0"
      cert_thumbprint     = "465E3197DA655543D29216A906BA3913B76A27B7"
      cert_valid_from     = "2020-10-27"
      cert_valid_to       = "2021-10-27"

      country             = "RU"
      state               = "???"
      locality            = "Omsk"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:fa:3d:ca:c1:9b:88:4b:44:ef:4f:81:54:11:84:d6:b0"
      )
}
