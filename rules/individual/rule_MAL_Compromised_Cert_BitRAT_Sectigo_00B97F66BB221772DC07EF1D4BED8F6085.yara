import "pe"

rule MAL_Compromised_Cert_BitRAT_Sectigo_00B97F66BB221772DC07EF1D4BED8F6085 {
   meta:
      description         = "Detects BitRAT with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-03-01"
      version             = "1.0"

      hash                = "6a28f7fb457fb484c1fbcceb41b10637345b18950b62df89c0a7689dd4f20d68"
      malware             = "BitRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "S-PRO d.o.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:b9:7f:66:bb:22:17:72:dc:07:ef:1d:4b:ed:8f:60:85"
      cert_thumbprint     = "FB4EFB3BFCEF8E9A667C8657F2E3C8FB7436666E"
      cert_valid_from     = "2021-03-01"
      cert_valid_to       = "2022-03-01"

      country             = "SI"
      state               = "???"
      locality            = "Ljubljana - Črnuče"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:b9:7f:66:bb:22:17:72:dc:07:ef:1d:4b:ed:8f:60:85"
      )
}
