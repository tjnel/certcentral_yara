import "pe"

rule MAL_Compromised_Cert_Latrodectus_SSL_com_30B2FD81E0057F656E7CDA84DDB2A2DD {
   meta:
      description         = "Detects Latrodectus with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-01"
      version             = "1.0"

      hash                = "be5bcdfc0dbe204001b071e8270bd6856ce6841c43338d8db914e045147b0e77"
      malware             = "Latrodectus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Lion Code Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "30:b2:fd:81:e0:05:7f:65:6e:7c:da:84:dd:b2:a2:dd"
      cert_thumbprint     = "E4E13418BCA7E3C1AE6E05812831592E2DE922AF"
      cert_valid_from     = "2025-09-01"
      cert_valid_to       = "2026-09-01"

      country             = "FI"
      state               = "Päijänne Tavastia"
      locality            = "Lahti"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "30:b2:fd:81:e0:05:7f:65:6e:7c:da:84:dd:b2:a2:dd"
      )
}
