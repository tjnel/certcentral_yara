import "pe"

rule MAL_Compromised_Cert_ClearFake_GlobalSign_530C9FC05D0B9D497263E8F7 {
   meta:
      description         = "Detects ClearFake with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-02-02"
      version             = "1.0"

      hash                = "96fcae9a77f7f3d69488f487abe9358146601500523d8b43aeef10b4f658d93a"
      malware             = "ClearFake"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Shantou Chenghai Rongsheng Arts Company Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "53:0c:9f:c0:5d:0b:9d:49:72:63:e8:f7"
      cert_thumbprint     = "38CE22B597B49AFEEE260D294C44E2C398CF384A"
      cert_valid_from     = "2024-02-02"
      cert_valid_to       = "2025-02-02"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Shantou"
      email               = "jasonwang@xiongsteng.net"
      rdn_serial_number   = "91440515324832161Q"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "53:0c:9f:c0:5d:0b:9d:49:72:63:e8:f7"
      )
}
