import "pe"

rule MAL_Compromised_Cert_BaoLoader_Sectigo_00EF8847BDBB45210B4215C99F8FED229E {
   meta:
      description         = "Detects BaoLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-28"
      version             = "1.0"

      hash                = "8dab0c6c0afcf6e1d07b0379f2487f62df7e644a8fad771387fc03e2bdf9db85"
      malware             = "BaoLoader"
      malware_type        = "Backdoor"
      malware_notes       = "This malware was originally used for adfraud but is a risk due to an arbitrary backdoor. For more information see https://expel.com/blog/the-history-of-appsuite-the-certs-of-the-baoloader-developer/ and https://www.gdatasoftware.com/blog/2025/08/38257-appsuite-pdf-editor-backdoor-analysis"

      signer              = "Byte Media Sdn Bhd"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:ef:88:47:bd:bb:45:21:0b:42:15:c9:9f:8f:ed:22:9e"
      cert_thumbprint     = "97C41250FB5655834AD0AD1487EBECDD2F8DA099"
      cert_valid_from     = "2025-05-28"
      cert_valid_to       = "2026-05-28"

      country             = "MY"
      state               = "Johor"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:ef:88:47:bd:bb:45:21:0b:42:15:c9:9f:8f:ed:22:9e"
      )
}
