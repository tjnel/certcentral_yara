import "pe"

rule MAL_Compromised_Cert_Unknown_Certum_339CD8746EF4CBB202D56AED53BFEA22 {
   meta:
      description         = "Detects Unknown with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-11"
      version             = "1.0"

      hash                = "b8f8578169a6ccbf059bc1e7cf6edeb1e5fbcd3ee0a53de617853c8f29cc351d"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Mianyang Yiduobao Network Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "33:9c:d8:74:6e:f4:cb:b2:02:d5:6a:ed:53:bf:ea:22"
      cert_thumbprint     = "9C97D603271813B6A591CEDAEA155070CB00F3AF"
      cert_valid_from     = "2025-02-11"
      cert_valid_to       = "2026-02-11"

      country             = "CN"
      state               = "Sichuan"
      locality            = "Mianyang"
      email               = "???"
      rdn_serial_number   = "91510705MA7DJ6K762"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "33:9c:d8:74:6e:f4:cb:b2:02:d5:6a:ed:53:bf:ea:22"
      )
}
