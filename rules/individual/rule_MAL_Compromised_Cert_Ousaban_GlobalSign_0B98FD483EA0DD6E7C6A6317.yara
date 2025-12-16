import "pe"

rule MAL_Compromised_Cert_Ousaban_GlobalSign_0B98FD483EA0DD6E7C6A6317 {
   meta:
      description         = "Detects Ousaban with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-13"
      version             = "1.0"

      hash                = "40c708f5f85591eab36738ba4df9c46b296bd417bec2c4f5fabfc27b7b5fb317"
      malware             = "Ousaban"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "PAGAMENTOS DIGITAIS LTDA"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "0b:98:fd:48:3e:a0:dd:6e:7c:6a:63:17"
      cert_thumbprint     = "19baf25862979bc0c7cb3971187128986beb6db4a4c6986b452a286850e570b0"
      cert_valid_from     = "2024-12-13"
      cert_valid_to       = "2025-12-14"

      country             = "BR"
      state               = "PARAIBA"
      locality            = "JOAO PESSOA"
      email               = "pagamentosdigitaais@gmail.com"
      rdn_serial_number   = "55.972.702/0001-29"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "0b:98:fd:48:3e:a0:dd:6e:7c:6a:63:17"
      )
}
