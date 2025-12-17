import "pe"

rule MAL_Compromised_Cert_FakeDocument_SSL_com_685779616B1D4A00F3A825E2365B3945 {
   meta:
      description         = "Detects FakeDocument with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-15"
      version             = "1.0"

      hash                = "200769e30e583f97dd8163427cbdcffe3d4ed040e566455996c6c231426f5b5a"
      malware             = "FakeDocument"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Sahlmén Software AB"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "68:57:79:61:6b:1d:4a:00:f3:a8:25:e2:36:5b:39:45"
      cert_thumbprint     = "3F6DAA2E5E9C3EFD5281B6C2BBA80F2004F7A709"
      cert_valid_from     = "2025-10-15"
      cert_valid_to       = "2026-10-15"

      country             = "SE"
      state               = "Halland County"
      locality            = "Kungsbacka"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "68:57:79:61:6b:1d:4a:00:f3:a8:25:e2:36:5b:39:45"
      )
}
