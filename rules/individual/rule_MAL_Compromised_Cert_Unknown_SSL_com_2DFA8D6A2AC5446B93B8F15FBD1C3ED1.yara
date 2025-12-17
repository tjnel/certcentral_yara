import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_2DFA8D6A2AC5446B93B8F15FBD1C3ED1 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-13"
      version             = "1.0"

      hash                = "496b7707e779c1aa2d22954037f5df17a0e528f4f3e97f89cbf40c795c57e36c"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Shantou City Pengjia Knitting Industry Co., Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "2d:fa:8d:6a:2a:c5:44:6b:93:b8:f1:5f:bd:1c:3e:d1"
      cert_thumbprint     = "E792FB73D372A1EF0E2593A478735D737BB0F29B"
      cert_valid_from     = "2024-09-13"
      cert_valid_to       = "2025-09-13"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Shantou"
      email               = "???"
      rdn_serial_number   = "9144051378488590X0"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "2d:fa:8d:6a:2a:c5:44:6b:93:b8:f1:5f:bd:1c:3e:d1"
      )
}
