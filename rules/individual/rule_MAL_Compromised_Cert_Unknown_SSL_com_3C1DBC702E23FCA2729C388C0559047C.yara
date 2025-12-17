import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_3C1DBC702E23FCA2729C388C0559047C {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-27"
      version             = "1.0"

      hash                = "5ed8e5d8424c289ff146535c86b21495d682d155ce2e03cdaf24b21d19239481"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "INVOKESEC LLC"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "3c:1d:bc:70:2e:23:fc:a2:72:9c:38:8c:05:59:04:7c"
      cert_thumbprint     = "318970192EFF90907D07918A0FAF61A6F2D1F0AA"
      cert_valid_from     = "2025-02-27"
      cert_valid_to       = "2026-03-06"

      country             = "US"
      state               = "Utah"
      locality            = "Lehi"
      email               = "???"
      rdn_serial_number   = "13421273-0160"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "3c:1d:bc:70:2e:23:fc:a2:72:9c:38:8c:05:59:04:7c"
      )
}
