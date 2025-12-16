import "pe"

rule MAL_Compromised_Cert_HijackLoader_Certum_1F880EA0C7617F15B8550E78C3350A29 {
   meta:
      description         = "Detects HijackLoader with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-23"
      version             = "1.0"

      hash                = "ede6d11f1c8e2613674de05d20ec52a9931d33dfc04d8b5c0f1ff0243fc982a8"
      malware             = "HijackLoader"
      malware_type        = "Initial access tool"
      malware_notes       = ""

      signer              = "Jinan Lu'an Information Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "1f:88:0e:a0:c7:61:7f:15:b8:55:0e:78:c3:35:0a:29"
      cert_thumbprint     = "192BDD3C9045E3181CF844E3C8DF1B59283525AE"
      cert_valid_from     = "2025-10-23"
      cert_valid_to       = "2026-10-23"

      country             = "CN"
      state               = "山东省"
      locality            = "济南市"
      email               = "???"
      rdn_serial_number   = "91370100MA94FUXT8E"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "1f:88:0e:a0:c7:61:7f:15:b8:55:0e:78:c3:35:0a:29"
      )
}
