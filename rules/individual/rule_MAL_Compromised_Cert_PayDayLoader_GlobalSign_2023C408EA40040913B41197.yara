import "pe"

rule MAL_Compromised_Cert_PayDayLoader_GlobalSign_2023C408EA40040913B41197 {
   meta:
      description         = "Detects PayDayLoader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-25"
      version             = "1.0"

      hash                = "82d2b0397dba3749c0444a70a197edaf4c862d815f00c2c4b47746c8e11da4f7"
      malware             = "PayDayLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Wuhan Nuochenxing Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "20:23:c4:08:ea:40:04:09:13:b4:11:97"
      cert_thumbprint     = "3C71900AAAA75A93FCF53D5EA207D29423C20A16"
      cert_valid_from     = "2025-04-25"
      cert_valid_to       = "2026-04-26"

      country             = "CN"
      state               = "Hubei"
      locality            = "Wuhan"
      email               = "???"
      rdn_serial_number   = "91420100MA49JDXD83"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "20:23:c4:08:ea:40:04:09:13:b4:11:97"
      )
}
