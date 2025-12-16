import "pe"

rule MAL_Compromised_Cert_QuasarRAT_SSL_com_2E0166B936533F45D5DD693122092E35 {
   meta:
      description         = "Detects QuasarRAT with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-30"
      version             = "1.0"

      hash                = "8b648a9eb5283d67a7e17b76d6f0e795ef9d47dc78bb30c4a98428ef0078415c"
      malware             = "QuasarRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Tangshan Jimin Information Technology Partnership Enterprise(LP)"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "2e:01:66:b9:36:53:3f:45:d5:dd:69:31:22:09:2e:35"
      cert_thumbprint     = "9FD0CCC95444813A9D9ABECAE11E39C30640E537"
      cert_valid_from     = "2024-12-30"
      cert_valid_to       = "2025-12-30"

      country             = "CN"
      state               = "Hebei"
      locality            = "Tangshan"
      email               = "???"
      rdn_serial_number   = "91130202MA0F6L3T78"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "2e:01:66:b9:36:53:3f:45:d5:dd:69:31:22:09:2e:35"
      )
}
