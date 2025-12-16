import "pe"

rule MAL_Compromised_Cert_AsyncRAT_SSL_com_49E5E5F9E6B6D7F24FABE0429D2E9989 {
   meta:
      description         = "Detects AsyncRAT with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-25"
      version             = "1.0"

      hash                = "5a720bf1f2099c701a7bffba78c0c50288984e10b24b32c110e570c787674a50"
      malware             = "AsyncRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Taiga Revolution Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "49:e5:e5:f9:e6:b6:d7:f2:4f:ab:e0:42:9d:2e:99:89"
      cert_thumbprint     = "E23E04DA6C7A0382B847C04680CDE029F2C3CD98"
      cert_valid_from     = "2024-12-25"
      cert_valid_to       = "2025-12-25"

      country             = "FI"
      state               = "Pohjois-Pohjanmaa"
      locality            = "Kiiminki"
      email               = "???"
      rdn_serial_number   = "2847642-2"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "49:e5:e5:f9:e6:b6:d7:f2:4f:ab:e0:42:9d:2e:99:89"
      )
}
