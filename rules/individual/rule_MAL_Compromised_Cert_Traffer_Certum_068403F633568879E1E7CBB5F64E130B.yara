import "pe"

rule MAL_Compromised_Cert_Traffer_Certum_068403F633568879E1E7CBB5F64E130B {
   meta:
      description         = "Detects Traffer with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-13"
      version             = "1.0"

      hash                = "e94ed7457376352421a70929bd1e92161101e0693d713eeb0de57b45f8e18a3f"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = "Fake meeting software targeting jobseekers. Ref: https://cybersecuritynews.com/web3-developer-environments-targeted-by-social-engineering-campaign/"

      signer              = "Shaanxi Shaogekaifei Information Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "06:84:03:f6:33:56:88:79:e1:e7:cb:b5:f6:4e:13:0b"
      cert_thumbprint     = "B77B04BD3E2B744C19E238D0B76312B97DA8B048"
      cert_valid_from     = "2025-11-13"
      cert_valid_to       = "2026-11-13"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "06:84:03:f6:33:56:88:79:e1:e7:cb:b5:f6:4e:13:0b"
      )
}
