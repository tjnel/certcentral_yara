import "pe"

rule MAL_Compromised_Cert_QuasarRAT_SSL_com_0AFDA52EC44C7F7ADF710EA694A78DC9 {
   meta:
      description         = "Detects QuasarRAT with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-17"
      version             = "1.0"

      hash                = "e4922484284c90de832ea50a4e2866490af799b31dfcb81f5d4034c3ce8b6bbf"
      malware             = "QuasarRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "XTRA Software, s.r.o."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "0a:fd:a5:2e:c4:4c:7f:7a:df:71:0e:a6:94:a7:8d:c9"
      cert_thumbprint     = "36DE4CB9AD93B90EE12E2B3F8FD71F20F586F2C2"
      cert_valid_from     = "2025-04-17"
      cert_valid_to       = "2026-04-17"

      country             = "CZ"
      state               = "Praha, Hlavní město"
      locality            = "Praha"
      email               = "???"
      rdn_serial_number   = "24251950"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "0a:fd:a5:2e:c4:4c:7f:7a:df:71:0e:a6:94:a7:8d:c9"
      )
}
