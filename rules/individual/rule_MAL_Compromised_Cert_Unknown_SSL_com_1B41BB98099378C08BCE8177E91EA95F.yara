import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_1B41BB98099378C08BCE8177E91EA95F {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-30"
      version             = "1.0"

      hash                = "52599407c9ae090cd6aa29ee55f1bbaa549a9b5e5fe7cd6343cb937ea5999a20"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Hebei Qingyun Chemical Technology Co., Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "1b:41:bb:98:09:93:78:c0:8b:ce:81:77:e9:1e:a9:5f"
      cert_thumbprint     = "86C4E1E5233489A64645A144B13358CB63DCDB4E"
      cert_valid_from     = "2024-08-30"
      cert_valid_to       = "2025-08-29"

      country             = "CN"
      state               = "Hebei"
      locality            = "Shijiazhuang"
      email               = "???"
      rdn_serial_number   = "911301012360419332"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "1b:41:bb:98:09:93:78:c0:8b:ce:81:77:e9:1e:a9:5f"
      )
}
