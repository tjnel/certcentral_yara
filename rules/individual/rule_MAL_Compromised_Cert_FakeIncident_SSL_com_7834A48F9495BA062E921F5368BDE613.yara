import "pe"

rule MAL_Compromised_Cert_FakeIncident_SSL_com_7834A48F9495BA062E921F5368BDE613 {
   meta:
      description         = "Detects FakeIncident with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-18"
      version             = "1.0"

      hash                = "0058a199029f28cec3dbd33f13b066d0029bedb89be7515bcf2b17d88b76cf58"
      malware             = "FakeIncident"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Medi-Info Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "78:34:a4:8f:94:95:ba:06:2e:92:1f:53:68:bd:e6:13"
      cert_thumbprint     = "6C9413D810D528001EB356AD473A29AB9E94FAE2"
      cert_valid_from     = "2025-07-18"
      cert_valid_to       = "2026-07-18"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "Espoo"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "78:34:a4:8f:94:95:ba:06:2e:92:1f:53:68:bd:e6:13"
      )
}
