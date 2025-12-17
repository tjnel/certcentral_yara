import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_SSL_com_2B364A266B662217E23527D86CB66017 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-10"
      version             = "1.0"

      hash                = "8c8c535e458d9aaf346c5acb3402ce4f9223a845a805ad4c9d5d13a7f5485562"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "LUCKY7 VENTURES LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "2b:36:4a:26:6b:66:22:17:e2:35:27:d8:6c:b6:60:17"
      cert_thumbprint     = "B887E53FCA162CDAE20C1F9340FBF5AE390DE324"
      cert_valid_from     = "2025-09-10"
      cert_valid_to       = "2026-09-10"

      country             = "GB"
      state               = "???"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "2b:36:4a:26:6b:66:22:17:e2:35:27:d8:6c:b6:60:17"
      )
}
