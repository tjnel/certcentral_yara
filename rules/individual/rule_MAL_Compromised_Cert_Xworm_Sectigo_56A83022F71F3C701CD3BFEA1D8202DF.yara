import "pe"

rule MAL_Compromised_Cert_Xworm_Sectigo_56A83022F71F3C701CD3BFEA1D8202DF {
   meta:
      description         = "Detects Xworm with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-16"
      version             = "1.0"

      hash                = "86cdddef536b2d56b43e91095abd41a465db9baffedb1aae557eac1bef7b7439"
      malware             = "Xworm"
      malware_type        = "Unknown"
      malware_notes       = "Fake document posing as a receipt, connecting to Xworm-style C2. Ref: https://app.any.run/tasks/7e4e6698-71c1-4af1-a019-628ee7520bad"

      signer              = "ATF TEXTİLE DIŞ TİCARET SANAYİ LİMİTED ŞİRKETİ"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "56:a8:30:22:f7:1f:3c:70:1c:d3:bf:ea:1d:82:02:df"
      cert_thumbprint     = "6B5C88EBF21962A0BC23713385A75A52913AE31A"
      cert_valid_from     = "2026-01-16"
      cert_valid_to       = "2027-01-16"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "56:a8:30:22:f7:1f:3c:70:1c:d3:bf:ea:1d:82:02:df"
      )
}
