import "pe"

rule MAL_Compromised_Cert_BatLoader_SSL_com_1F5F6C8F6F37E026CE572643B6BB3BBD {
   meta:
      description         = "Detects BatLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-09"
      version             = "1.0"

      hash                = "a88a61b2dab40e651798aa312d069dac8085f9e7a2e5bffb6ef42360b7f775b0"
      malware             = "BatLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "See this article to learn more about Batloader: https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html"

      signer              = "AJM It Services Limited"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "1f:5f:6c:8f:6f:37:e0:26:ce:57:26:43:b6:bb:3b:bd"
      cert_thumbprint     = "269A65EB485E50A979458DDAAF64E48FF0808D57"
      cert_valid_from     = "2024-07-09"
      cert_valid_to       = "2025-07-09"

      country             = "GB"
      state               = "???"
      locality            = "Southend-On-Sea"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "1f:5f:6c:8f:6f:37:e0:26:ce:57:26:43:b6:bb:3b:bd"
      )
}
