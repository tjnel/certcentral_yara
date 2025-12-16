import "pe"

rule MAL_Compromised_Cert_CastleLoader_Certum_6FE1CA02563A3BBED8D2D0E978A09C49 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-06"
      version             = "1.0"

      hash                = "c413b2e2c71ea31bc366c95b3554a36ff1d662b365c7f06768d53d44e441f7d5"
      malware             = "CastleLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "This is an initial access tool that is frequenty used to load infostealers or remote access tools, sold as Malware-as-a-Service: https://www.ibm.com/think/x-force/dissecting-castlebot-maas-operation"

      signer              = "Soft Insanity Oy"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "6f:e1:ca:02:56:3a:3b:be:d8:d2:d0:e9:78:a0:9c:49"
      cert_thumbprint     = "9FFC26C90A70AF5DF2A1885E49EAB61B4EC39FA4"
      cert_valid_from     = "2025-11-06"
      cert_valid_to       = "2026-11-06"

      country             = "FI"
      state               = "Kanta-Häme"
      locality            = "HÄMEENLINNA"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "6f:e1:ca:02:56:3a:3b:be:d8:d2:d0:e9:78:a0:9c:49"
      )
}
