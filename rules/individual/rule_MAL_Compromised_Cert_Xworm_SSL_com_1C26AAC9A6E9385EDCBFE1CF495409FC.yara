import "pe"

rule MAL_Compromised_Cert_Xworm_SSL_com_1C26AAC9A6E9385EDCBFE1CF495409FC {
   meta:
      description         = "Detects Xworm with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-17"
      version             = "1.0"

      hash                = "b067a06d797c4563c036c1de2668c6bc1a7dbfbd0d07755066287b8b1822b588"
      malware             = "Xworm"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "N SILVA COMERCIO E SERVICOS TURISTICOS LTDA"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "1c:26:aa:c9:a6:e9:38:5e:dc:bf:e1:cf:49:54:09:fc"
      cert_thumbprint     = "E9563CF80F9A2BF08BD60D692E86618D0897B9B9"
      cert_valid_from     = "2025-07-17"
      cert_valid_to       = "2026-07-17"

      country             = "BR"
      state               = "Bahia"
      locality            = "Santa Cruz da Vitória"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "1c:26:aa:c9:a6:e9:38:5e:dc:bf:e1:cf:49:54:09:fc"
      )
}
