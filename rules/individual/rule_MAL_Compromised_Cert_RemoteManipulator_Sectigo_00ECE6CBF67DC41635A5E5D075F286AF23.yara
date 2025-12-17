import "pe"

rule MAL_Compromised_Cert_RemoteManipulator_Sectigo_00ECE6CBF67DC41635A5E5D075F286AF23 {
   meta:
      description         = "Detects RemoteManipulator with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-10-22"
      version             = "1.0"

      hash                = "6dda990d8073fee71cedeabd622f6d7a9be6fb2e696bda71e7b709f1c08f5e36"
      malware             = "RemoteManipulator"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "THRANE AGENTUR ApS"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:ec:e6:cb:f6:7d:c4:16:35:a5:e5:d0:75:f2:86:af:23"
      cert_thumbprint     = "979D470B4E782EF6BE34DED465988FB089302204"
      cert_valid_from     = "2020-10-22"
      cert_valid_to       = "2021-10-22"

      country             = "DK"
      state               = "Hovedstaden"
      locality            = "Klampenborg"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:ec:e6:cb:f6:7d:c4:16:35:a5:e5:d0:75:f2:86:af:23"
      )
}
