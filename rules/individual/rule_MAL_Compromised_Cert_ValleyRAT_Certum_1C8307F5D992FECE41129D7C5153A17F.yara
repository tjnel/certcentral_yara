import "pe"

rule MAL_Compromised_Cert_ValleyRAT_Certum_1C8307F5D992FECE41129D7C5153A17F {
   meta:
      description         = "Detects ValleyRAT with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-19"
      version             = "1.0"

      hash                = "9c1a85f711fb500d70760d40e9e57854555dfc225fae68bb035f4a0167324e29"
      malware             = "ValleyRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "陕西斯慧嘉网络科技有限公司"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "1c:83:07:f5:d9:92:fe:ce:41:12:9d:7c:51:53:a1:7f"
      cert_thumbprint     = "EA71A12738E997CE48A9A5A194D1666B1A6533C7"
      cert_valid_from     = "2024-06-19"
      cert_valid_to       = "2025-06-19"

      country             = "CN"
      state               = "Shanxi"
      locality            = "Xi'an"
      email               = "???"
      rdn_serial_number   = "91610104MAC98H859T"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "1c:83:07:f5:d9:92:fe:ce:41:12:9d:7c:51:53:a1:7f"
      )
}
