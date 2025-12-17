import "pe"

rule MAL_Compromised_Cert_Unknown_DigiCert_0B886032861D9553C68F803313A98975 {
   meta:
      description         = "Detects Unknown with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-03-11"
      version             = "1.0"

      hash                = "f361f5ec213b861dc4a76eb2835d70e6739321539ad216ea5dc416c1dc026528"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Micro-Star International CO., LTD."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert SHA2 Assured ID Code Signing CA"
      cert_serial         = "0b:88:60:32:86:1d:95:53:c6:8f:80:33:13:a9:89:75"
      cert_thumbprint     = "11AB64D74470575BE416909B06204FE042EDD38C"
      cert_valid_from     = "2021-03-11"
      cert_valid_to       = "2024-06-05"

      country             = "TW"
      state               = "New Taipei City"
      locality            = "Zhonghe District"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert SHA2 Assured ID Code Signing CA" and
         sig.serial == "0b:88:60:32:86:1d:95:53:c6:8f:80:33:13:a9:89:75"
      )
}
