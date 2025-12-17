import "pe"

rule MAL_Compromised_Cert_Unknown_Certum_545B84509ABF85E386011CEE69F61882 {
   meta:
      description         = "Detects Unknown with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-21"
      version             = "1.0"

      hash                = "748149df038a771986691e3f54afea609ceb9fbfcbec92145beb586bec039e6a"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Meizhou Fisherman Network Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "54:5b:84:50:9a:bf:85:e3:86:01:1c:ee:69:f6:18:82"
      cert_thumbprint     = "C9CC769DE207133042E6608499199D222BEFD824"
      cert_valid_from     = "2025-05-21"
      cert_valid_to       = "2026-05-21"

      country             = "CN"
      state               = "广东省"
      locality            = "梅州市"
      email               = "???"
      rdn_serial_number   = "91441403MA4UNLKT9A"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "54:5b:84:50:9a:bf:85:e3:86:01:1c:ee:69:f6:18:82"
      )
}
