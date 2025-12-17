import "pe"

rule MAL_Compromised_Cert_AntiemuleLoader_Certum_451062113F2D48D7D109C713A5F4CAEB {
   meta:
      description         = "Detects AntiemuleLoader with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-14"
      version             = "1.0"

      hash                = "d8c67587a04132e9ea0ebbe34212507836d47e03b594ad1e7739789941ac6495"
      malware             = "AntiemuleLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "Based on domains used in the delivery, this malware was seen used in a campaign targeting shipping companies: https://www.proofpoint.com/us/blog/threat-insight/remote-access-real-cargo-cybercriminals-targeting-trucking-and-logistics"

      signer              = "Shandong Shangchuan Smart Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "45:10:62:11:3f:2d:48:d7:d1:09:c7:13:a5:f4:ca:eb"
      cert_thumbprint     = "A3A37ED6615BC9AA84876904710E117F694BD753"
      cert_valid_from     = "2025-11-14"
      cert_valid_to       = "2026-11-14"

      country             = "CN"
      state               = "山东省"
      locality            = "德州市"
      email               = "???"
      rdn_serial_number   = "91371402MAC7JPQR3Y"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "45:10:62:11:3f:2d:48:d7:d1:09:c7:13:a5:f4:ca:eb"
      )
}
