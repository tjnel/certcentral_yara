import "pe"

rule MAL_Compromised_Cert_SecTopRAT_ArechClient2_SSL_com_6F80EC3395E1E11086F3349C54447A3F {
   meta:
      description         = "Detects SecTopRAT,ArechClient2 with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-25"
      version             = "1.0"

      hash                = "605573bb6ca5ff1331a45f5250d74f1c620cc7101d7d89a958278065092c6f4a"
      malware             = "SecTopRAT,ArechClient2"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Nightmoon Software"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "6f:80:ec:33:95:e1:e1:10:86:f3:34:9c:54:44:7a:3f"
      cert_thumbprint     = "4DE4CB6AD4FB48B3146064B666369F8C33F90C4B"
      cert_valid_from     = "2024-11-25"
      cert_valid_to       = "2025-11-25"

      country             = "FR"
      state               = "Île-de-France"
      locality            = "Paris"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "6f:80:ec:33:95:e1:e1:10:86:f3:34:9c:54:44:7a:3f"
      )
}
