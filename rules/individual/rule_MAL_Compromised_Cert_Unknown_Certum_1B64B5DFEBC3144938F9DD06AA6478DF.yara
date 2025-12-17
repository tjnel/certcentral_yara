import "pe"

rule MAL_Compromised_Cert_Unknown_Certum_1B64B5DFEBC3144938F9DD06AA6478DF {
   meta:
      description         = "Detects Unknown with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-02"
      version             = "1.0"

      hash                = "7d2dd19806f618dbae67470702e0536c82f331907644afd7db402c687eae0f44"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Yinzhang Huang"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "1b:64:b5:df:eb:c3:14:49:38:f9:dd:06:aa:64:78:df"
      cert_thumbprint     = "0EE3059CECEF5D3CF836A7C313DC1C39502FE8D4"
      cert_valid_from     = "2024-12-02"
      cert_valid_to       = "2025-12-02"

      country             = "CN"
      state               = "广西"
      locality            = "桂林市"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "1b:64:b5:df:eb:c3:14:49:38:f9:dd:06:aa:64:78:df"
      )
}
