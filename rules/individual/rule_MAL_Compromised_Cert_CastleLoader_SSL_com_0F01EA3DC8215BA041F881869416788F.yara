import "pe"

rule MAL_Compromised_Cert_CastleLoader_SSL_com_0F01EA3DC8215BA041F881869416788F {
   meta:
      description         = "Detects CastleLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-17"
      version             = "1.0"

      hash                = "27f24adab8c696069e22233860851dd8654a846700483f6c4a9a8aa05f1b27db"
      malware             = "CastleLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "This is an initial access tool that is frequenty used to load infostealers or remote access tools, sold as Malware-as-a-Service: https://www.ibm.com/think/x-force/dissecting-castlebot-maas-operation"

      signer              = "FORMES CONSTRUCTION LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "0f:01:ea:3d:c8:21:5b:a0:41:f8:81:86:94:16:78:8f"
      cert_thumbprint     = "5000029E947762E7A72558C82A4BA814C112D724"
      cert_valid_from     = "2025-07-17"
      cert_valid_to       = "2026-06-13"

      country             = "GB"
      state               = "Oxfordshire"
      locality            = "Faringdon"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "0f:01:ea:3d:c8:21:5b:a0:41:f8:81:86:94:16:78:8f"
      )
}
