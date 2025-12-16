import "pe"

rule MAL_Compromised_Cert_WeEvilProxy_GlobalSign_12D7480FA2F83AD92D8F01E5 {
   meta:
      description         = "Detects WeEvilProxy with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-20"
      version             = "1.0"

      hash                = "bda71a81ee8959960d868f1806154035730ad107ecf01cad37b8349fd0e89a34"
      malware             = "WeEvilProxy"
      malware_type        = "Infostealer"
      malware_notes       = "This malware primarily targets cryptocurrencies. It is distributed through advertisements targing crypto users: https://labs.withsecure.com/publications/weevilproxy"

      signer              = "LLC Resurs"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "12:d7:48:0f:a2:f8:3a:d9:2d:8f:01:e5"
      cert_thumbprint     = "6FF61050D30E5F52E64EC31CEA3870BE67B855E5"
      cert_valid_from     = "2025-06-20"
      cert_valid_to       = "2026-06-21"

      country             = "RU"
      state               = "Novosibirsk Oblast"
      locality            = "Novosibirsk"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "12:d7:48:0f:a2:f8:3a:d9:2d:8f:01:e5"
      )
}
