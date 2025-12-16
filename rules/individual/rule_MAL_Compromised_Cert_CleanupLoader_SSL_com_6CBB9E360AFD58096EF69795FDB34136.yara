import "pe"

rule MAL_Compromised_Cert_CleanupLoader_SSL_com_6CBB9E360AFD58096EF69795FDB34136 {
   meta:
      description         = "Detects CleanupLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-16"
      version             = "1.0"

      hash                = "bd965b3c1b2b3c146cb12767a44646bbd17ee72257aafbcf37c58a398c2e084f"
      malware             = "CleanupLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Zhongyao Changye (Tangshan) Network Technology Co., Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "6c:bb:9e:36:0a:fd:58:09:6e:f6:97:95:fd:b3:41:36"
      cert_thumbprint     = "D762B08E8FC7C6FE23F380D8A825AAD29B84C5B0"
      cert_valid_from     = "2024-05-16"
      cert_valid_to       = "2025-05-15"

      country             = "CN"
      state               = "Hebei"
      locality            = "Tangshan"
      email               = "???"
      rdn_serial_number   = "91130293MA0G03BG0Q"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "6c:bb:9e:36:0a:fd:58:09:6e:f6:97:95:fd:b3:41:36"
      )
}
