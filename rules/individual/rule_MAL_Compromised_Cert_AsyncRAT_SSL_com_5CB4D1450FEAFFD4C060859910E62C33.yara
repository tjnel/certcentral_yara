import "pe"

rule MAL_Compromised_Cert_AsyncRAT_SSL_com_5CB4D1450FEAFFD4C060859910E62C33 {
   meta:
      description         = "Detects AsyncRAT with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-16"
      version             = "1.0"

      hash                = "9515dac6a4ff603dec56b68d9644ce438a76273199fa5723b52cb25dda396c59"
      malware             = "AsyncRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Crystal It Solution Sp. z o.o."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "5c:b4:d1:45:0f:ea:ff:d4:c0:60:85:99:10:e6:2c:33"
      cert_thumbprint     = "17FEAFFE0F55899DAD8297C9D9C5AD8A2A521E81"
      cert_valid_from     = "2025-04-16"
      cert_valid_to       = "2026-04-16"

      country             = "PL"
      state               = "Masovian Voivodeship"
      locality            = "Warszawa"
      email               = "???"
      rdn_serial_number   = "0000673463"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "5c:b4:d1:45:0f:ea:ff:d4:c0:60:85:99:10:e6:2c:33"
      )
}
