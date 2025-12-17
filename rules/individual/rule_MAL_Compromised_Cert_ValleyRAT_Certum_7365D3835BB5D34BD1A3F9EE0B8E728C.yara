import "pe"

rule MAL_Compromised_Cert_ValleyRAT_Certum_7365D3835BB5D34BD1A3F9EE0B8E728C {
   meta:
      description         = "Detects ValleyRAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-28"
      version             = "1.0"

      hash                = "877dadf7ce4684878ea086cbd4c111d5dfb87c2659366f6df5079047fbea13db"
      malware             = "ValleyRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Yangzhou Bai'ao Information Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "73:65:d3:83:5b:b5:d3:4b:d1:a3:f9:ee:0b:8e:72:8c"
      cert_thumbprint     = "4C3BF297DCE27630DB010B618A7F0C630F704B99"
      cert_valid_from     = "2025-11-28"
      cert_valid_to       = "2026-11-28"

      country             = "CN"
      state               = "Jiangsu"
      locality            = "Yangzhou"
      email               = "???"
      rdn_serial_number   = "91321091MAEWX1H02N"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "73:65:d3:83:5b:b5:d3:4b:d1:a3:f9:ee:0b:8e:72:8c"
      )
}
