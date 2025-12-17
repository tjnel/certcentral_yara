import "pe"

rule MAL_Compromised_Cert_CastleLoader_SSL_com_1AB29E886DBAF6A0942AA73DA480DD91 {
   meta:
      description         = "Detects CastleLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-13"
      version             = "1.0"

      hash                = "24fb4e14f8e2f2b663e3221132aec06f30eae68aea9ad4e927407ce6049a9ac1"
      malware             = "CastleLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "This is an initial access tool that is frequenty used to load infostealers or remote access tools, sold as Malware-as-a-Service: https://www.ibm.com/think/x-force/dissecting-castlebot-maas-operation"

      signer              = "INTYNA EXIM PRIVATE LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "1a:b2:9e:88:6d:ba:f6:a0:94:2a:a7:3d:a4:80:dd:91"
      cert_thumbprint     = "F51F2B1D2EF5C7CE9C60E2B3914ADDCB8072355E"
      cert_valid_from     = "2025-10-13"
      cert_valid_to       = "2026-10-13"

      country             = "IN"
      state               = "Delhi"
      locality            = "Delhi"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "1a:b2:9e:88:6d:ba:f6:a0:94:2a:a7:3d:a4:80:dd:91"
      )
}
