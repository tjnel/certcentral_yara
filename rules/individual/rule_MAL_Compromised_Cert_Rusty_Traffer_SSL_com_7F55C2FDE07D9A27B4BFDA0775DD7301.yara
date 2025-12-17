import "pe"

rule MAL_Compromised_Cert_Rusty_Traffer_SSL_com_7F55C2FDE07D9A27B4BFDA0775DD7301 {
   meta:
      description         = "Detects Rusty Traffer with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-10"
      version             = "1.0"

      hash                = "928040d5f16f0bdba85d5b16121a99aa03e0547e48ea92b10aa6bb9bc050692e"
      malware             = "Rusty Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "FORMTECH MAKER SP Z O O"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "7f:55:c2:fd:e0:7d:9a:27:b4:bf:da:07:75:dd:73:01"
      cert_thumbprint     = "8E928A6DA83C2C32EBB92888F592AA385710D3A6"
      cert_valid_from     = "2025-07-10"
      cert_valid_to       = "2026-07-10"

      country             = "PL"
      state               = "Lower Silesian Voivodeship"
      locality            = "Gniechowice"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "7f:55:c2:fd:e0:7d:9a:27:b4:bf:da:07:75:dd:73:01"
      )
}
