import "pe"

rule MAL_Compromised_Cert_ValleyRAT_Certum_4DDD9F79FFA78EB06C8C638334836ACF {
   meta:
      description         = "Detects ValleyRAT with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-23"
      version             = "1.0"

      hash                = "bcbb74f7b54f471f5d98ef24ae9b472f2cbe3efe04d6c6ff1088c63ddce290cf"
      malware             = "ValleyRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "成都金源启铭网络有限公司"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "4d:dd:9f:79:ff:a7:8e:b0:6c:8c:63:83:34:83:6a:cf"
      cert_thumbprint     = "45CD69622857EC75D216B7AFF0F02B4B7B464968"
      cert_valid_from     = "2025-07-23"
      cert_valid_to       = "2026-07-23"

      country             = "CN"
      state               = "Sichuan"
      locality            = "Chengdu"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "4d:dd:9f:79:ff:a7:8e:b0:6c:8c:63:83:34:83:6a:cf"
      )
}
