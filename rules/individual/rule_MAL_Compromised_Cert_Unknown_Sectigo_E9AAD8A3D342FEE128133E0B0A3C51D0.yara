import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_E9AAD8A3D342FEE128133E0B0A3C51D0 {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-13"
      version             = "1.0"

      hash                = "839c4e05847d6a8662bc3ade6298372e6fd546e74d7e205e549419782043899d"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "55.604.504 Rafael Ferreira de Carvalho"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV E36"
      cert_serial         = "e9:aa:d8:a3:d3:42:fe:e1:28:13:3e:0b:0a:3c:51:d0"
      cert_thumbprint     = "a620cf23dbe296979675f9a0eb5c003595b7b48ac7d0067b5760a1d31545e030"
      cert_valid_from     = "2025-01-13"
      cert_valid_to       = "2025-10-30"

      country             = "BR"
      state               = "Distrito Federal"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "55.604.504/0001-02"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV E36" and
         sig.serial == "e9:aa:d8:a3:d3:42:fe:e1:28:13:3e:0b:0a:3c:51:d0"
      )
}
