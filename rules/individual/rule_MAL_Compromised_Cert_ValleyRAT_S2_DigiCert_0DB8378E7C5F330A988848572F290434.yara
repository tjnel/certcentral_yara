import "pe"

rule MAL_Compromised_Cert_ValleyRAT_S2_DigiCert_0DB8378E7C5F330A988848572F290434 {
   meta:
      description         = "Detects ValleyRAT S2 with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-06"
      version             = "1.0"

      hash                = "a8a42814c253ca5e93e81be5bd69149ff71b9ac3024420614fba37fb0834b3c0"
      malware             = "ValleyRAT S2"
      malware_type        = "Unknown"
      malware_notes       = "Second-stage payloads of ValleyRAT. Context: https://apophis133.medium.com/valleyrat-s2-chinese-campaign-4504b890f416"

      signer              = "Hangzhou Saifan Technology Co., Ltd."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0d:b8:37:8e:7c:5f:33:0a:98:88:48:57:2f:29:04:34"
      cert_thumbprint     = "E16902882C4386CE2B7043513ADECC5E95D5F07C"
      cert_valid_from     = "2024-06-06"
      cert_valid_to       = "2026-07-07"

      country             = "CN"
      state               = "Zhejiang"
      locality            = "Hangzhou"
      email               = "???"
      rdn_serial_number   = "913301045773160340"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0d:b8:37:8e:7c:5f:33:0a:98:88:48:57:2f:29:04:34"
      )
}
