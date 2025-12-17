import "pe"

rule MAL_Compromised_Cert_LummaStealer_SSL_com_4F12A0A5569392FC0B41C3D077E6586D {
   meta:
      description         = "Detects LummaStealer with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-06"
      version             = "1.0"

      hash                = "1626516aad9026976a6eaa4e637e8de95cb9d1203e99f50e94f25ea7a06c34f9"
      malware             = "LummaStealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "SIFA ESTATE LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "4f:12:a0:a5:56:93:92:fc:0b:41:c3:d0:77:e6:58:6d"
      cert_thumbprint     = "3CF0E45215994AE97A21B5C487369592EA24B1D2"
      cert_valid_from     = "2025-03-06"
      cert_valid_to       = "2026-03-06"

      country             = "KE"
      state               = "???"
      locality            = "Nairobi"
      email               = "???"
      rdn_serial_number   = "CPR/2010/81740"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "4f:12:a0:a5:56:93:92:fc:0b:41:c3:d0:77:e6:58:6d"
      )
}
