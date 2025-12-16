import "pe"

rule MAL_Compromised_Cert_Traffer_SSL_com_425BAAE83C0A911C727A6C5714F16CA8 {
   meta:
      description         = "Detects Traffer with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-05"
      version             = "1.0"

      hash                = "cd03e9300bb9b923e4af97cde2b2b896272d803b74e42c6234f57610788053b9"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "JUST MAX SP Z O O"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "42:5b:aa:e8:3c:0a:91:1c:72:7a:6c:57:14:f1:6c:a8"
      cert_thumbprint     = "5637D3DD966E8335F62B87ED8825D355C37C6D29"
      cert_valid_from     = "2025-05-05"
      cert_valid_to       = "2026-05-05"

      country             = "PL"
      state               = "Masovian Voivodeship"
      locality            = "Warsaw"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "42:5b:aa:e8:3c:0a:91:1c:72:7a:6c:57:14:f1:6c:a8"
      )
}
