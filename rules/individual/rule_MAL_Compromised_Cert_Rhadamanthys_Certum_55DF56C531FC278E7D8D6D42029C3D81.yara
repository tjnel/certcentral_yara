import "pe"

rule MAL_Compromised_Cert_Rhadamanthys_Certum_55DF56C531FC278E7D8D6D42029C3D81 {
   meta:
      description         = "Detects Rhadamanthys with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-20"
      version             = "1.0"

      hash                = "b37a0a7ff6ad23dc71339f86ffa4223327dfcb015d24c32e74cf4ac8a272d1a8"
      malware             = "Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "沈阳海颖网络科技信息咨询有限公司"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "55:df:56:c5:31:fc:27:8e:7d:8d:6d:42:02:9c:3d:81"
      cert_thumbprint     = "2F97799141972D08C59F68D1C7BCB9B2B07132FB"
      cert_valid_from     = "2024-12-20"
      cert_valid_to       = "2025-12-20"

      country             = "CN"
      state               = "Liaoning"
      locality            = "Shenyang"
      email               = "???"
      rdn_serial_number   = "91210106MA10YN4A4Y"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "55:df:56:c5:31:fc:27:8e:7d:8d:6d:42:02:9c:3d:81"
      )
}
