import "pe"

rule MAL_Compromised_Cert_FakeIvanti_Certum_03DA155639347FBB8241450243F3818E {
   meta:
      description         = "Detects FakeIvanti with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-11"
      version             = "1.0"

      hash                = "40d77718fbb05123f17e5aea3e65f937eda0f9f8866d866158d4ec3d69ab867e"
      malware             = "FakeIvanti"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Hefei Qiangwei Network Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "03:da:15:56:39:34:7f:bb:82:41:45:02:43:f3:81:8e"
      cert_thumbprint     = "EC443DE3ED3D17515CE137FE271C885B4F09F03E"
      cert_valid_from     = "2025-09-11"
      cert_valid_to       = "2026-09-11"

      country             = "CN"
      state               = "安徽省"
      locality            = "合肥市"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "03:da:15:56:39:34:7f:bb:82:41:45:02:43:f3:81:8e"
      )
}
