import "pe"

rule MAL_Compromised_Cert_WeEvilProxy_SSL_com_2F8440CF0284CB8329777B52EF44CA8A {
   meta:
      description         = "Detects WeEvilProxy with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-31"
      version             = "1.0"

      hash                = "7c66e462325232e88681b37e73f118d35ac23f54da59e3786f89c88da193f729"
      malware             = "WeEvilProxy"
      malware_type        = "Infostealer"
      malware_notes       = "This malware primarily targets cryptocurrencies. It is distributed through advertisements targing crypto users: https://labs.withsecure.com/publications/weevilproxy"

      signer              = "IT Consulting Timo Lehtinen Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "2f:84:40:cf:02:84:cb:83:29:77:7b:52:ef:44:ca:8a"
      cert_thumbprint     = "84A6BCF027BA5DFE74586F937A437BA6D2309E17"
      cert_valid_from     = "2025-03-31"
      cert_valid_to       = "2026-03-31"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "Helsinki"
      email               = "???"
      rdn_serial_number   = "2147547-8"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "2f:84:40:cf:02:84:cb:83:29:77:7b:52:ef:44:ca:8a"
      )
}
