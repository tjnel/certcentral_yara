import "pe"

rule MAL_Compromised_Cert_CastleLoader_SSL_com_511CD84EA13903383B6D752F8AD73B7D {
   meta:
      description         = "Detects CastleLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-08"
      version             = "1.0"

      hash                = "169f1204aed49ec40813b0df5f39232971c74cde1f89f045ad033451710b5c9d"
      malware             = "CastleLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "This is an initial access tool that is frequenty used to load infostealers or remote access tools, sold as Malware-as-a-Service: https://www.ibm.com/think/x-force/dissecting-castlebot-maas-operation"

      signer              = "Code Staff B.V."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "51:1c:d8:4e:a1:39:03:38:3b:6d:75:2f:8a:d7:3b:7d"
      cert_thumbprint     = "3C3B922EF201699C67C3FB81563B3646AF0CB59D"
      cert_valid_from     = "2025-08-08"
      cert_valid_to       = "2026-08-08"

      country             = "NL"
      state               = "North Holland"
      locality            = "Alkmaar"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "51:1c:d8:4e:a1:39:03:38:3b:6d:75:2f:8a:d7:3b:7d"
      )
}
