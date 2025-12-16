import "pe"

rule MAL_Compromised_Cert_CastleLoader_GlobalSign_2C204F0654E5D1D07E9E09B7 {
   meta:
      description         = "Detects CastleLoader with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-14"
      version             = "1.0"

      hash                = "8f3fc820def7b492876b38d021c904aafc60c379e8ad58cac81eee05bf41ee77"
      malware             = "CastleLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "This is an initial access tool that is frequenty used to load infostealers or remote access tools, sold as Malware-as-a-Service: https://www.ibm.com/think/x-force/dissecting-castlebot-maas-operation"

      signer              = "LLC Company Magnon"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "2c:20:4f:06:54:e5:d1:d0:7e:9e:09:b7"
      cert_thumbprint     = "6AB349E04755799C3ACD7460645D081FF12A45BB"
      cert_valid_from     = "2025-03-14"
      cert_valid_to       = "2026-03-15"

      country             = "RU"
      state               = "Sverdlovsk Oblast"
      locality            = "Yekaterinburg"
      email               = "???"
      rdn_serial_number   = "1186658011264"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "2c:20:4f:06:54:e5:d1:d0:7e:9e:09:b7"
      )
}
