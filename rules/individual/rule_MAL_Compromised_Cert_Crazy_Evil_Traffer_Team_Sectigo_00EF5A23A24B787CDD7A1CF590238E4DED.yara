import "pe"

rule MAL_Compromised_Cert_Crazy_Evil_Traffer_Team_Sectigo_00EF5A23A24B787CDD7A1CF590238E4DED {
   meta:
      description         = "Detects Crazy Evil Traffer Team with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-09"
      version             = "1.0"

      hash                = "992998cd7083f73bb8fa0adbeb1c2f0564a887670d8fb986943dafd3f7278d0f"
      malware             = "Crazy Evil Traffer Team"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "Redstrikevn Company Limited"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV E36"
      cert_serial         = "00:ef:5a:23:a2:4b:78:7c:dd:7a:1c:f5:90:23:8e:4d:ed"
      cert_thumbprint     = "F4702F1327F5F19EB94C6868659765CC073192B2"
      cert_valid_from     = "2025-02-09"
      cert_valid_to       = "2026-01-16"

      country             = "VN"
      state               = "Ho Chi Minh"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "0318798119"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV E36" and
         sig.serial == "00:ef:5a:23:a2:4b:78:7c:dd:7a:1c:f5:90:23:8e:4d:ed"
      )
}
