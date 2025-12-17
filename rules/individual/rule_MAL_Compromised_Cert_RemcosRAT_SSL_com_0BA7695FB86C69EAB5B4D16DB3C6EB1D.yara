import "pe"

rule MAL_Compromised_Cert_RemcosRAT_SSL_com_0BA7695FB86C69EAB5B4D16DB3C6EB1D {
   meta:
      description         = "Detects RemcosRAT with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-18"
      version             = "1.0"

      hash                = "05badedbfa2ca6164741b2b475ed60ea405a97e40ef9a4108bdb8bd115c318da"
      malware             = "RemcosRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Annett Holdings, Inc."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "0b:a7:69:5f:b8:6c:69:ea:b5:b4:d1:6d:b3:c6:eb:1d"
      cert_thumbprint     = "A6E91D18B354BB1BBFA7E1EBEDFB0981040FAE17"
      cert_valid_from     = "2025-07-18"
      cert_valid_to       = "2026-07-18"

      country             = "US"
      state               = "Iowa"
      locality            = "Des Moines"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "0b:a7:69:5f:b8:6c:69:ea:b5:b4:d1:6d:b3:c6:eb:1d"
      )
}
