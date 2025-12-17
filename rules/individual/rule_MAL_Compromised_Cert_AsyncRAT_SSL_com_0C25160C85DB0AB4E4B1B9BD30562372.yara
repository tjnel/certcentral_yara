import "pe"

rule MAL_Compromised_Cert_AsyncRAT_SSL_com_0C25160C85DB0AB4E4B1B9BD30562372 {
   meta:
      description         = "Detects AsyncRAT with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-17"
      version             = "1.0"

      hash                = "b44728674cfd2749db422893ebc649aea95f89ed5813b7a82571504d5d965953"
      malware             = "AsyncRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "James Burnell"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "0c:25:16:0c:85:db:0a:b4:e4:b1:b9:bd:30:56:23:72"
      cert_thumbprint     = "86F1603F0E5192A854DC04DB695594CEDEA8F46E"
      cert_valid_from     = "2025-09-17"
      cert_valid_to       = "2026-09-17"

      country             = "US"
      state               = "Oregon"
      locality            = "La Grande"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "0c:25:16:0c:85:db:0a:b4:e4:b1:b9:bd:30:56:23:72"
      )
}
