import "pe"

rule MAL_Compromised_Cert_PatchWork_SSL_com_0C03FD84E8E8569F0253D099494690D4 {
   meta:
      description         = "Detects PatchWork with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-02-05"
      version             = "1.0"

      hash                = "a68eff3ae040246a305b4aff70b09ab557d900dc6954ef498b030f87c5fedf0b"
      malware             = "PatchWork"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Software Consulting Group Limited"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "0c:03:fd:84:e8:e8:56:9f:02:53:d0:99:49:46:90:d4"
      cert_thumbprint     = "B185F504221A54E5219A063C8056F79736F7E98E"
      cert_valid_from     = "2024-02-05"
      cert_valid_to       = "2025-02-04"

      country             = "GB"
      state               = "England"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "0c:03:fd:84:e8:e8:56:9f:02:53:d0:99:49:46:90:d4"
      )
}
