import "pe"

rule MAL_Compromised_Cert_Winos_SSL_com_72C9DB722E93A08BF09A00BD7963687C {
   meta:
      description         = "Detects Winos with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-18"
      version             = "1.0"

      hash                = "18fa694a30be09438ae1e94e23806bfe5edc7c4f2edbe15ff63c9016ddc94112"
      malware             = "Winos"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ZELCORE TECHNOLOGIES INC."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "72:c9:db:72:2e:93:a0:8b:f0:9a:00:bd:79:63:68:7c"
      cert_thumbprint     = "FD450B62877A6EC9D1D72D3D31125FAE70B86C3F"
      cert_valid_from     = "2024-11-18"
      cert_valid_to       = "2025-11-22"

      country             = "US"
      state               = "Delaware"
      locality            = "Dover"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "72:c9:db:72:2e:93:a0:8b:f0:9a:00:bd:79:63:68:7c"
      )
}
