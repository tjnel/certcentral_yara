import "pe"

rule MAL_Compromised_Cert_Latam_Trojan_Banker_SSL_com_3FE13C520C9758C4A4A7084862E2C191 {
   meta:
      description         = "Detects Latam Trojan Banker with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-11-03"
      version             = "1.0"

      hash                = "6c3d977bfeccd287c82f6f1693b12cf5f2732397342d8831e27cfab4023852d3"
      malware             = "Latam Trojan Banker"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SIA GSM design"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "3f:e1:3c:52:0c:97:58:c4:a4:a7:08:48:62:e2:c1:91"
      cert_thumbprint     = "3CC34712BC3881634197D75216B99B99FBFE567A"
      cert_valid_from     = "2023-11-03"
      cert_valid_to       = "2024-11-02"

      country             = "LV"
      state               = "Ādažu pagasts"
      locality            = "Ādaži"
      email               = "???"
      rdn_serial_number   = "40203258355"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "3f:e1:3c:52:0c:97:58:c4:a4:a7:08:48:62:e2:c1:91"
      )
}
