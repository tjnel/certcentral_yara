import "pe"

rule MAL_Compromised_Cert_CastleLoader_SSL_com_63F98070213489715A8D224F58E1C1D5 {
   meta:
      description         = "Detects CastleLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-27"
      version             = "1.0"

      hash                = "02a2b2af427a65e85e44575ebfbc088d5972a689fd1e7e025ee5d229f3e0ace9"
      malware             = "CastleLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "This is an initial access tool that is frequenty used to load infostealers or remote access tools, sold as Malware-as-a-Service: https://www.ibm.com/think/x-force/dissecting-castlebot-maas-operation"

      signer              = "BRACKET-SOFT SP Z O O"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "63:f9:80:70:21:34:89:71:5a:8d:22:4f:58:e1:c1:d5"
      cert_thumbprint     = "9FB6F13DEDFBF3E58FADEA0D0AF0D5F8223BF05E"
      cert_valid_from     = "2025-05-27"
      cert_valid_to       = "2026-05-27"

      country             = "PL"
      state               = "Kuyavian-Pomeranian Voivodeship"
      locality            = "Toruń"
      email               = "???"
      rdn_serial_number   = "0000609189"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "63:f9:80:70:21:34:89:71:5a:8d:22:4f:58:e1:c1:d5"
      )
}
