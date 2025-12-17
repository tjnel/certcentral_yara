import "pe"

rule MAL_Compromised_Cert_Metasploit_SSL_com_0B26B62AB59556B229BD9905D33D43E8 {
   meta:
      description         = "Detects Metasploit with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-24"
      version             = "1.0"

      hash                = "f8b313d8d8ee0a622b1eea8cb148323b6194228014f11402967f065351e473ab"
      malware             = "Metasploit"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Roger Alexander Gonzalez Castillo"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "0b:26:b6:2a:b5:95:56:b2:29:bd:99:05:d3:3d:43:e8"
      cert_thumbprint     = "C5EF53AF49EA288D56C5A2EAB81CA2D480AA810E"
      cert_valid_from     = "2024-12-24"
      cert_valid_to       = "2025-10-21"

      country             = "EC"
      state               = "Sucumbíos Province"
      locality            = "Nueva Loja"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "0b:26:b6:2a:b5:95:56:b2:29:bd:99:05:d3:3d:43:e8"
      )
}
