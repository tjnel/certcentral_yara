import "pe"

rule MAL_Compromised_Cert_ValleyRAT_Certum_4C4C225E13B1CBEA59C3A9B50AE2B94D {
   meta:
      description         = "Detects ValleyRAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-21"
      version             = "1.0"

      hash                = "1107160996aad02e3d44572030599713712db1e7538a346d5bd885f1ff88fdaa"
      malware             = "ValleyRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "合肥高好频商贸有限公司"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "4c:4c:22:5e:13:b1:cb:ea:59:c3:a9:b5:0a:e2:b9:4d"
      cert_thumbprint     = "A7C18AAF8AC708C18BAA8C8F0CD19C2780EF8F42"
      cert_valid_from     = "2025-05-21"
      cert_valid_to       = "2026-05-21"

      country             = "CN"
      state               = "安徽"
      locality            = "合肥"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "4c:4c:22:5e:13:b1:cb:ea:59:c3:a9:b5:0a:e2:b9:4d"
      )
}
