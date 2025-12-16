import "pe"

rule MAL_Compromised_Cert_AveMariaRAT_SSL_com_2848CDB4CE4AE5FE43996CA627EFCA4A {
   meta:
      description         = "Detects AveMariaRAT with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-02"
      version             = "1.0"

      hash                = "61477ea2220941345454e63fac8daf508fb97643c73d82d5dd925a5cd472df8b"
      malware             = "AveMariaRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "EHT DESIGN PTY LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "28:48:cd:b4:ce:4a:e5:fe:43:99:6c:a6:27:ef:ca:4a"
      cert_thumbprint     = "4E4851E9A89B22260590165D653C4F6EC49619A8"
      cert_valid_from     = "2025-04-02"
      cert_valid_to       = "2026-04-02"

      country             = "AU"
      state               = "Victoria"
      locality            = "Melbourne"
      email               = "???"
      rdn_serial_number   = "68 166 123 397"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "28:48:cd:b4:ce:4a:e5:fe:43:99:6c:a6:27:ef:ca:4a"
      )
}
