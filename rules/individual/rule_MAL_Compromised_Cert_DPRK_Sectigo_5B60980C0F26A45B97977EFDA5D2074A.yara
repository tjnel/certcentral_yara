import "pe"

rule MAL_Compromised_Cert_DPRK_Sectigo_5B60980C0F26A45B97977EFDA5D2074A {
   meta:
      description         = "Detects DPRK with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-09-15"
      version             = "1.0"

      hash                = "e19ce3bd1cbd980082d3c55a4ac1eb3af4d9e7adf108afb1861372f9c7fe0b76"
      malware             = "DPRK"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "DATASOLUTION Inc"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "5b:60:98:0c:0f:26:a4:5b:97:97:7e:fd:a5:d2:07:4a"
      cert_thumbprint     = "37CBD552AA5FE99C92CC92EFF7C8F236D48A0A45"
      cert_valid_from     = "2022-09-15"
      cert_valid_to       = "2025-10-17"

      country             = "KR"
      state               = "Seoul"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "5b:60:98:0c:0f:26:a4:5b:97:97:7e:fd:a5:d2:07:4a"
      )
}
