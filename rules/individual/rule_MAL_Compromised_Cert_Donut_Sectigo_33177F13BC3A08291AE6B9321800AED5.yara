import "pe"

rule MAL_Compromised_Cert_Donut_Sectigo_33177F13BC3A08291AE6B9321800AED5 {
   meta:
      description         = "Detects Donut with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-19"
      version             = "1.0"

      hash                = "fa31ac5d5383a107f45c6ea47d94684517c01b78503560573af3f202524f06be"
      malware             = "Donut"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "55.604.504 Rafael Ferreira de Carvalho"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV E36"
      cert_serial         = "33:17:7f:13:bc:3a:08:29:1a:e6:b9:32:18:00:ae:d5"
      cert_thumbprint     = "8DD0D57D77BB142020C571408CAFEBA394084AF0"
      cert_valid_from     = "2025-03-19"
      cert_valid_to       = "2025-10-30"

      country             = "BR"
      state               = "Distrito Federal"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "55.604.504/0001-02"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV E36" and
         sig.serial == "33:17:7f:13:bc:3a:08:29:1a:e6:b9:32:18:00:ae:d5"
      )
}
