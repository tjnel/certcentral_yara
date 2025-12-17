import "pe"

rule MAL_Compromised_Cert_Amadey_stage2_Sectigo_008A47780EA1C57823F9139D9DFE59F68F {
   meta:
      description         = "Detects Amadey_stage2 with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-11"
      version             = "1.0"

      hash                = "eeb072d287cbacae3ffd0645731c708afde360f9974756c366fa101732315191"
      malware             = "Amadey_stage2"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Gucheng County Jiemai Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:8a:47:78:0e:a1:c5:78:23:f9:13:9d:9d:fe:59:f6:8f"
      cert_thumbprint     = "5E6D4DAF176E81B6921E78BF16AAE6321D61AA88"
      cert_valid_from     = "2025-08-11"
      cert_valid_to       = "2026-08-11"

      country             = "CN"
      state               = "Hubei Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91420625MAD6RUTA1M"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:8a:47:78:0e:a1:c5:78:23:f9:13:9d:9d:fe:59:f6:8f"
      )
}
