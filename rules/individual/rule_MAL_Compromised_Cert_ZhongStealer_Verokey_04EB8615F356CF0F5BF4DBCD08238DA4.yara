import "pe"

rule MAL_Compromised_Cert_ZhongStealer_Verokey_04EB8615F356CF0F5BF4DBCD08238DA4 {
   meta:
      description         = "Detects ZhongStealer with compromised cert (Verokey)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-24"
      version             = "1.0"

      hash                = "b5fb40289c795be46e746bce7cfb8641bd4d619e49fae62f4998c7915f831e5e"
      malware             = "ZhongStealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware relies on CDNs to pull down second stage components. See https://x.com/malwrhunterteam/status/1997368057702842676?s=20"

      signer              = "山西荣升源科贸有限公司"
      cert_issuer_short   = "Verokey"
      cert_issuer         = "Verokey High Assurance Secure Code EV"
      cert_serial         = "04:eb:86:15:f3:56:cf:0f:5b:f4:db:cd:08:23:8d:a4"
      cert_thumbprint     = "428FEE9B772BD7E56987E864AD8C83B5721E717F"
      cert_valid_from     = "2024-10-24"
      cert_valid_to       = "2026-06-18"

      country             = "CN"
      state               = "山西省"
      locality            = "太原市"
      email               = "???"
      rdn_serial_number   = "91140105MA0LK0WH8B"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Verokey High Assurance Secure Code EV" and
         sig.serial == "04:eb:86:15:f3:56:cf:0f:5b:f4:db:cd:08:23:8d:a4"
      )
}
