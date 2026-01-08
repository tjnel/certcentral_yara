import "pe"

rule MAL_Compromised_Cert_PureLogstealer_Xworm_SSL_com_18C1F0E7CAC9039CAFF80EADDF948EE1 {
   meta:
      description         = "Detects PureLogstealer, Xworm with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-13"
      version             = "1.0"

      hash                = "aa412cb3954e212d73da73ceb3fb468d74b2acbbdeb09ff3eb015c914bede0a0"
      malware             = "PureLogstealer, Xworm"
      malware_type        = "Infostealer"
      malware_notes       = ""

      signer              = "AURORA SOLUCOES & TURISMO LTDA"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "18:c1:f0:e7:ca:c9:03:9c:af:f8:0e:ad:df:94:8e:e1"
      cert_thumbprint     = "F609EE655A952FE42AA7078686D86372BECE422E"
      cert_valid_from     = "2025-10-13"
      cert_valid_to       = "2026-10-13"

      country             = "BR"
      state               = "Santa Catarina"
      locality            = "Blumenau"
      email               = "???"
      rdn_serial_number   = "58.339.882/0001-02"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "18:c1:f0:e7:ca:c9:03:9c:af:f8:0e:ad:df:94:8e:e1"
      )
}
