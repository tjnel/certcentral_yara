import "pe"

rule MAL_Compromised_Cert_Rhadamanthys_Certum_585EFDA35CFE245E41EBB2D47043C5DC {
   meta:
      description         = "Detects Rhadamanthys with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-13"
      version             = "1.0"

      hash                = "ff6fcdd0e22270484451763d71f31f244b6805ed288f2310fb5d924309176852"
      malware             = "Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "Fuzhou Gulou Haosenzi E-commerce Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "58:5e:fd:a3:5c:fe:24:5e:41:eb:b2:d4:70:43:c5:dc"
      cert_thumbprint     = "066692E80D1F62F86CD773B055425C79D854F5A0"
      cert_valid_from     = "2024-08-13"
      cert_valid_to       = "2025-08-13"

      country             = "CN"
      state               = "Fujian"
      locality            = "Fuzhou"
      email               = "???"
      rdn_serial_number   = "91350102MA8T626L6C"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "58:5e:fd:a3:5c:fe:24:5e:41:eb:b2:d4:70:43:c5:dc"
      )
}
