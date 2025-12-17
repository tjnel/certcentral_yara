import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_Certum_06B6D93159708182E93C6EA793F5EA1F {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-22"
      version             = "1.0"

      hash                = "9fa68287729336e8d77a29ce1a9c71ff47e8ad54e4627623ca6ec581f3285146"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Beijing Ruiyunteng Network Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "06:b6:d9:31:59:70:81:82:e9:3c:6e:a7:93:f5:ea:1f"
      cert_thumbprint     = "4761A2225BC36B9CDDA3B26553DCEA94C79AC150"
      cert_valid_from     = "2024-08-22"
      cert_valid_to       = "2025-08-22"

      country             = "CN"
      state               = "Beijing"
      locality            = "Beijing"
      email               = "???"
      rdn_serial_number   = "91110229MA001HBGX8"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "06:b6:d9:31:59:70:81:82:e9:3c:6e:a7:93:f5:ea:1f"
      )
}
