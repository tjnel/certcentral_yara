import "pe"

rule MAL_Compromised_Cert_Stealer5000_SSL_com_59ABFE373E657805504B83D792EA951B {
   meta:
      description         = "Detects Stealer5000 with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-12"
      version             = "1.0"

      hash                = "b75f706e64f1cfb417f5d02dad09fd5b808a2dfc3237c06b4709fe16b1442511"
      malware             = "Stealer5000"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "IT Alasin Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "59:ab:fe:37:3e:65:78:05:50:4b:83:d7:92:ea:95:1b"
      cert_thumbprint     = "13683C65EF9D2705B6EFE6CFE4F9122241A98F30"
      cert_valid_from     = "2025-06-12"
      cert_valid_to       = "2026-06-12"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "Vantaa"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "59:ab:fe:37:3e:65:78:05:50:4b:83:d7:92:ea:95:1b"
      )
}
