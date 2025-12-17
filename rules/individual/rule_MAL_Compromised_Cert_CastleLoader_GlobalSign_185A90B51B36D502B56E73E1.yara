import "pe"

rule MAL_Compromised_Cert_CastleLoader_GlobalSign_185A90B51B36D502B56E73E1 {
   meta:
      description         = "Detects CastleLoader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-27"
      version             = "1.0"

      hash                = "376856afa1fbb89426d78f35a22816dc5ad8ff78810420046076a87caf3b0691"
      malware             = "CastleLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "This is an initial access tool that is frequenty used to load infostealers or remote access tools, sold as Malware-as-a-Service: https://www.ibm.com/think/x-force/dissecting-castlebot-maas-operation"

      signer              = "MARKUS LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "18:5a:90:b5:1b:36:d5:02:b5:6e:73:e1"
      cert_thumbprint     = "86ABDC193500E33E06346F02F7A880DD895B550A"
      cert_valid_from     = "2025-09-27"
      cert_valid_to       = "2025-11-13"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "18:5a:90:b5:1b:36:d5:02:b5:6e:73:e1"
      )
}
