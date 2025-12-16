import "pe"

rule MAL_Compromised_Cert_Dridex_Sectigo_00E573D9C8B403C41BD59FFA0A8EFD4168 {
   meta:
      description         = "Detects Dridex with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2019-07-15"
      version             = "1.0"

      hash                = "4fccd38f504290cf5c70e7336071a90a064303c7fdf5c17f7c38001768bce115"
      malware             = "Dridex"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "VERONIKA 2"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:e5:73:d9:c8:b4:03:c4:1b:d5:9f:fa:0a:8e:fd:41:68"
      cert_thumbprint     = "C6B324434D24AF606214A78D9D030F313C1550CF"
      cert_valid_from     = "2019-07-15"
      cert_valid_to       = "2020-06-27"

      country             = "RU"
      state               = "???"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:e5:73:d9:c8:b4:03:c4:1b:d5:9f:fa:0a:8e:fd:41:68"
      )
}
