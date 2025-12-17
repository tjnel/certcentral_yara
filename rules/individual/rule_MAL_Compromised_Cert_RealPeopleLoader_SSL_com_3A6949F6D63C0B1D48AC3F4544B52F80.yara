import "pe"

rule MAL_Compromised_Cert_RealPeopleLoader_SSL_com_3A6949F6D63C0B1D48AC3F4544B52F80 {
   meta:
      description         = "Detects RealPeopleLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-12"
      version             = "1.0"

      hash                = "3f5c435d0f8adad303318007bfcea2a3c6a8f6f7db49af5747fff1a88ff91672"
      malware             = "RealPeopleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "IT WEST POLAND SP Z O O"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "3a:69:49:f6:d6:3c:0b:1d:48:ac:3f:45:44:b5:2f:80"
      cert_thumbprint     = "93607709B8DA3F9A62C2400FB30E3FA7CD1F0C22"
      cert_valid_from     = "2025-04-12"
      cert_valid_to       = "2026-04-12"

      country             = "PL"
      state               = "???"
      locality            = "Wroclaw"
      email               = "???"
      rdn_serial_number   = "0000974845"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "3a:69:49:f6:d6:3c:0b:1d:48:ac:3f:45:44:b5:2f:80"
      )
}
