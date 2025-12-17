import "pe"

rule MAL_Compromised_Cert_Batloader_SSL_com_5E65623207A0F5322CEDC57005E5CB41 {
   meta:
      description         = "Detects Batloader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-02-09"
      version             = "1.0"

      hash                = "470a322864eb9fb96afc1eb64db7a39200df1b6f58bcdfc0138304ccd63b8963"
      malware             = "Batloader"
      malware_type        = "Initial access tool"
      malware_notes       = "See this article to learn more about Batloader: https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html"

      signer              = "JM CRYPTO PTY LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "5e:65:62:32:07:a0:f5:32:2c:ed:c5:70:05:e5:cb:41"
      cert_thumbprint     = "924D5781F34F8A9C08D8FCEC9BF563D9287FF829"
      cert_valid_from     = "2023-02-09"
      cert_valid_to       = "2024-02-09"

      country             = "AU"
      state               = "Western Australia"
      locality            = "Hilton"
      email               = "???"
      rdn_serial_number   = "623 744 801"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "5e:65:62:32:07:a0:f5:32:2c:ed:c5:70:05:e5:cb:41"
      )
}
