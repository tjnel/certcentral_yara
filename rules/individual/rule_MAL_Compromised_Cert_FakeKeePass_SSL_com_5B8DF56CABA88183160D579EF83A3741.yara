import "pe"

rule MAL_Compromised_Cert_FakeKeePass_SSL_com_5B8DF56CABA88183160D579EF83A3741 {
   meta:
      description         = "Detects FakeKeePass with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-01"
      version             = "1.0"

      hash                = "a5404e3f9d5358065d99c8175d60157600587a1103bd8a5461012eb42d4e9ef8"
      malware             = "FakeKeePass"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "POPSHINE MEDIA LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "5b:8d:f5:6c:ab:a8:81:83:16:0d:57:9e:f8:3a:37:41"
      cert_thumbprint     = "CE06E8CCE961C70F3F414FFE66FDB96FBBEA4E71"
      cert_valid_from     = "2025-08-01"
      cert_valid_to       = "2026-08-01"

      country             = "GB"
      state               = "???"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "5b:8d:f5:6c:ab:a8:81:83:16:0d:57:9e:f8:3a:37:41"
      )
}
