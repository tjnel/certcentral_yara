import "pe"

rule MAL_Compromised_Cert_RUS_55_Certum_43CFEE96B948B5B672754F51A0E6E719 {
   meta:
      description         = "Detects RUS-55 with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-12"
      version             = "1.0"

      hash                = "c85a23cddbc9979c0c9c8040218c41b0a0008fee9e60cf8a885f94594eff04ea"
      malware             = "RUS-55"
      malware_type        = "Remote access tool"
      malware_notes       = "File was distributed as a trojanized RVTools installer. See analysis here https://tria.ge/251217-ny7gksen6v/behavioral1"

      signer              = "Taiyuan Tataomi Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "43:cf:ee:96:b9:48:b5:b6:72:75:4f:51:a0:e6:e7:19"
      cert_thumbprint     = "0C707864C9FF609E40497A7C6920C0B2A01CF174"
      cert_valid_from     = "2025-11-12"
      cert_valid_to       = "2026-11-12"

      country             = "CN"
      state               = "Shanxi"
      locality            = "Taiyuan"
      email               = "???"
      rdn_serial_number   = "91140105MADC8HF4XN"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "43:cf:ee:96:b9:48:b5:b6:72:75:4f:51:a0:e6:e7:19"
      )
}
