import "pe"

rule MAL_Compromised_Cert_AsyncRAT_Sectigo_00A8DBD769A7546486C6C775C25610859A {
   meta:
      description         = "Detects AsyncRAT with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-09"
      version             = "1.0"

      hash                = "98e7a6162d91a30d2b9bcc50bb18a9bde57a8e127111c5eacb80d87b99f7a91a"
      malware             = "AsyncRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Taiyuan Ningjiangqiang Technology Co., Ltd"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:a8:db:d7:69:a7:54:64:86:c6:c7:75:c2:56:10:85:9a"
      cert_thumbprint     = "01DBDF52BC78D40D69E3A318B2EF0DC68C42B94C"
      cert_valid_from     = "2025-09-09"
      cert_valid_to       = "2026-09-09"

      country             = "CN"
      state               = "Shanxi Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:a8:db:d7:69:a7:54:64:86:c6:c7:75:c2:56:10:85:9a"
      )
}
