import "pe"

rule MAL_Compromised_Cert_PayDayLoader_SSL_com_1F9173767331DE57953640A27B097968 {
   meta:
      description         = "Detects PayDayLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-04"
      version             = "1.0"

      hash                = "5ca6b15a14af2c8e9024e6168a8b30b84b49aeb593af31ecd7d0bbfc0a82c067"
      malware             = "PayDayLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Weifang Hanya Cultural Communication Co., Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "1f:91:73:76:73:31:de:57:95:36:40:a2:7b:09:79:68"
      cert_thumbprint     = "FC9982AA34B9F886E060953048FC3A5465DCB41B"
      cert_valid_from     = "2025-03-04"
      cert_valid_to       = "2026-03-02"

      country             = "CN"
      state               = "Shandong"
      locality            = "Weifang"
      email               = "???"
      rdn_serial_number   = "91370724MA7CKD064J"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "1f:91:73:76:73:31:de:57:95:36:40:a2:7b:09:79:68"
      )
}
