import "pe"

rule MAL_Compromised_Cert_OnionProxy_SSL_com_35B1041EC0C7C7181DCC7339D1094981 {
   meta:
      description         = "Detects OnionProxy with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-06"
      version             = "1.0"

      hash                = "a7480fac99ee466a2c14393464dd84e10f8362910796d73122674d7e87ce8499"
      malware             = "OnionProxy"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Creditamore Software"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "35:b1:04:1e:c0:c7:c7:18:1d:cc:73:39:d1:09:49:81"
      cert_thumbprint     = "4AD468065B72D16C3C2100F5ED115A61EBE9993C"
      cert_valid_from     = "2025-02-06"
      cert_valid_to       = "2026-02-06"

      country             = "FR"
      state               = "Île-de-France"
      locality            = "Paris"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "35:b1:04:1e:c0:c7:c7:18:1d:cc:73:39:d1:09:49:81"
      )
}
