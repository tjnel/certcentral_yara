import "pe"

rule MAL_Compromised_Cert_CastleLoader_GlobalSign_737C5C461D3864AC4F089E26 {
   meta:
      description         = "Detects CastleLoader with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-18"
      version             = "1.0"

      hash                = "770007f02a48fe4b445af19c07a4f3a2131fcdd53d68e20c8345eafae5843974"
      malware             = "CastleLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "This is an initial access tool that is frequenty used to load infostealers or remote access tools, sold as Malware-as-a-Service: https://www.ibm.com/think/x-force/dissecting-castlebot-maas-operation"

      signer              = "GAUAMRIT NUTRICARE PRIVATE LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "73:7c:5c:46:1d:38:64:ac:4f:08:9e:26"
      cert_thumbprint     = "1FDCD9EC6AF07FEBAAD53B05D12C7B415F817764"
      cert_valid_from     = "2025-06-18"
      cert_valid_to       = "2026-06-19"

      country             = "IN"
      state               = "Rajasthan"
      locality            = "Jaipur"
      email               = "gauamrit.kanaram@gmail.com"
      rdn_serial_number   = "U01100RJ2020PTC069509"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "73:7c:5c:46:1d:38:64:ac:4f:08:9e:26"
      )
}
